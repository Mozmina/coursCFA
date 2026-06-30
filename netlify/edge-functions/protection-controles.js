/*
  Protection des contrôles du site coursCFA.

  IMPORTANT :
  Le mot de passe n'est pas écrit dans ce fichier.
  Il est lu depuis la variable privée Netlify CONTROL_PASSWORD.

  Deux fonctionnements :
  1. Pages entièrement protégées : aucune partie du contrôle n'est envoyée sans mot de passe.
  2. Pages mixtes : les révisions restent visibles, mais l'onglet CCF/Contrôle
     est retiré de la réponse HTML tant que le mot de passe n'est pas validé.
*/

const COOKIE_NAME = "cfa_control_access";
const SESSION_VERSION = "cours-cfa-v2";
const SESSION_DURATION_SECONDS = 12 * 60 * 60;

const encoder = new TextEncoder();

/*
  Pages constituées uniquement d'un contrôle ou d'un corrigé sensible.
  Elles sont intégralement bloquées.
*/
const FULL_PAGE_PATHS = new Set([
  "/eval.html",
  "/eval",

  "/evalprop.html",
  "/evalprop",

  "/evalAlgo.html",
  "/evalAlgo",

  "/evalEquaCAP.html",
  "/evalEquaCAP",

  "/evalOptiqueCap.html",
  "/evalOptiqueCap",

  "/evalThermique.html",
  "/evalThermique",

  "/TPairesCorrection.html",
  "/TPairesCorrection",
]);

/*
  Pages qui contiennent à la fois des révisions publiques et un contrôle privé.
*/
const MIXED_PAGE_MODES = new Map([
  ["/Revision&CCF2.html", "revision-ccf2"],
  ["/Revision&CCF2", "revision-ccf2"],

  ["/BPONDES_rev+synthese+contr.html", "bp-ondes"],
  ["/BPONDES_rev+synthese+contr", "bp-ondes"],
]);

function normalizePath(pathname) {
  let decodedPath = pathname;

  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    decodedPath = pathname;
  }

  if (decodedPath.length > 1 && decodedPath.endsWith("/")) {
    decodedPath = decodedPath.slice(0, -1);
  }

  return decodedPath;
}

function toBase64Url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function constantTimeEqual(left, right) {
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  const length = Math.max(leftBytes.length, rightBytes.length);

  let difference = leftBytes.length ^ rightBytes.length;

  for (let index = 0; index < length; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }

  return difference === 0;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return new Uint8Array(digest);
}

async function passwordMatches(candidate, expected) {
  const [candidateHash, expectedHash] = await Promise.all([
    sha256(candidate),
    sha256(expected),
  ]);

  let difference = candidateHash.length ^ expectedHash.length;
  const length = Math.max(candidateHash.length, expectedHash.length);

  for (let index = 0; index < length; index += 1) {
    difference |= (candidateHash[index] ?? 0) ^ (expectedHash[index] ?? 0);
  }

  return difference === 0;
}

async function signSession(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(payload),
  );

  return toBase64Url(new Uint8Array(signature));
}

async function createSessionValue(secret) {
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_DURATION_SECONDS;
  const payload = `${SESSION_VERSION}|${expiresAt}`;
  const signature = await signSession(payload, secret);

  return `${expiresAt}.${signature}`;
}

async function sessionIsValid(cookieValue, secret) {
  if (!cookieValue || !secret) {
    return false;
  }

  const separatorIndex = cookieValue.indexOf(".");

  if (separatorIndex <= 0) {
    return false;
  }

  const expiresText = cookieValue.slice(0, separatorIndex);
  const suppliedSignature = cookieValue.slice(separatorIndex + 1);
  const expiresAt = Number(expiresText);

  if (!Number.isInteger(expiresAt)) {
    return false;
  }

  if (expiresAt <= Math.floor(Date.now() / 1000)) {
    return false;
  }

  const payload = `${SESSION_VERSION}|${expiresAt}`;
  const expectedSignature = await signSession(payload, secret);

  return constantTimeEqual(suppliedSignature, expectedSignature);
}

function sessionCookieHeader(value) {
  return [
    `${COOKIE_NAME}=${value}`,
    "Path=/",
    `Max-Age=${SESSION_DURATION_SECONDS}`,
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
  ].join("; ");
}

function expiredCookieHeader() {
  return [
    `${COOKIE_NAME}=`,
    "Path=/",
    "Max-Age=0",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
  ].join("; ");
}

function redirectResponse(location, cookieHeader = "") {
  const headers = new Headers({
    Location: location,
    "Cache-Control": "no-store",
  });

  if (cookieHeader) {
    headers.set("Set-Cookie", cookieHeader);
  }

  return new Response(null, {
    status: 303,
    headers,
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function loginPage(pathname, isMixedPage, errorMessage = "") {
  const safePath = escapeHtml(pathname);
  const safeError = escapeHtml(errorMessage);
  const action = `${safePath}?deverrouiller=1`;

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>Accès protégé - Cours CFA</title>

  <style>
    :root {
      --yellow: #f5c400;
      --yellow-dark: #d2a600;
      --ink: #20242a;
      --paper: #f3f4f5;
      --surface: #ffffff;
      --text: #252a30;
      --muted: #66707a;
      --line: #dfe3e7;
      --danger: #b42318;
    }

    * {
      box-sizing: border-box;
    }

    body {
      display: grid;
      min-height: 100vh;
      margin: 0;
      padding: 22px;
      place-items: center;
      color: var(--text);
      background:
        linear-gradient(135deg, rgba(245, 196, 0, 0.07) 25%, transparent 25%) 0 0 / 28px 28px,
        var(--paper);
      font-family: Arial, Helvetica, sans-serif;
    }

    .gate {
      width: min(440px, 100%);
      overflow: hidden;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: 0 22px 55px rgba(25, 31, 38, 0.16);
    }

    .gate-header {
      padding: 22px;
      color: white;
      background: var(--ink);
      border-bottom: 6px solid var(--yellow);
    }

    .label {
      display: inline-block;
      margin-bottom: 8px;
      color: var(--yellow);
      font-size: 0.75rem;
      font-weight: 900;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    h1 {
      margin: 0;
      font-size: 1.65rem;
      line-height: 1.1;
    }

    .gate-header p {
      margin: 8px 0 0;
      color: #d5dae0;
      line-height: 1.45;
    }

    form {
      padding: 22px;
    }

    label {
      display: block;
      margin-bottom: 7px;
      font-size: 0.88rem;
      font-weight: 850;
    }

    input {
      width: 100%;
      min-height: 48px;
      padding: 0 13px;
      color: var(--text);
      background: white;
      border: 1px solid var(--line);
      border-radius: 10px;
      outline: none;
      font: inherit;
      font-size: 1.08rem;
      letter-spacing: 0.15em;
    }

    input:focus {
      border-color: var(--yellow-dark);
      box-shadow: 0 0 0 4px rgba(245, 196, 0, 0.2);
    }

    button {
      width: 100%;
      min-height: 46px;
      margin-top: 13px;
      color: var(--ink);
      background: var(--yellow);
      border: 0;
      border-radius: 10px;
      font: inherit;
      font-weight: 900;
      cursor: pointer;
    }

    button:hover {
      background: #ffd52e;
    }

    .error {
      margin: 18px 22px 0;
      padding: 10px 12px;
      color: var(--danger);
      font-size: 0.88rem;
      font-weight: 750;
      background: #fff1f0;
      border: 1px solid #f3b6b0;
      border-radius: 9px;
    }

    .back {
      display: block;
      margin: 0 22px 22px;
      color: var(--muted);
      font-size: 0.82rem;
      font-weight: 750;
      text-align: center;
      text-decoration: none;
    }

    .back:hover {
      color: var(--ink);
      text-decoration: underline;
    }
  </style>
</head>

<body>
  <main class="gate">
    <header class="gate-header">
      <span class="label">Accès formateur</span>
      <h1>Ressource protégée</h1>
      <p>Entre le mot de passe pour ouvrir le contrôle.</p>
    </header>

    ${safeError ? `<p class="error" role="alert">${safeError}</p>` : ""}

    <form method="post" action="${action}">
      <label for="password">Mot de passe</label>
      <input
        id="password"
        name="password"
        type="password"
        inputmode="numeric"
        autocomplete="current-password"
        required
        autofocus
      >
      <button type="submit">Ouvrir le contrôle</button>
    </form>

    <a class="back" href="${isMixedPage ? safePath : "/index.html"}">
      ${isMixedPage ? "Retour aux révisions" : "Retour aux cours"}
    </a>
  </main>
</body>
</html>`;
}

function configurationErrorPage() {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="robots" content="noindex, nofollow">
  <title>Protection non configurée</title>
  <style>
    body {
      margin: 0;
      padding: 30px;
      color: #20242a;
      background: #f3f4f5;
      font-family: Arial, Helvetica, sans-serif;
    }

    main {
      max-width: 700px;
      margin: 40px auto;
      padding: 24px;
      background: white;
      border: 1px solid #dfe3e7;
      border-left: 8px solid #f5c400;
      border-radius: 12px;
    }

    h1 {
      margin-top: 0;
    }

    code {
      padding: 2px 5px;
      background: #eef1f3;
      border-radius: 5px;
    }
  </style>
</head>
<body>
  <main>
    <h1>Protection non configurée</h1>
    <p>
      Dans Netlify, ajoute les variables
      <code>CONTROL_PASSWORD</code> et
      <code>CONTROL_SESSION_SECRET</code>,
      puis relance un déploiement.
    </p>
  </main>
</body>
</html>`;
}

function noStoreHeaders(originalHeaders) {
  const headers = new Headers(originalHeaders);

  headers.delete("content-length");
  headers.delete("content-encoding");
  headers.delete("etag");
  headers.set("Cache-Control", "private, no-store");

  return headers;
}

function responseWithHtml(html, originalResponse, extraHeaders = {}) {
  const headers = noStoreHeaders(originalResponse.headers);

  for (const [name, value] of Object.entries(extraHeaders)) {
    headers.set(name, value);
  }

  headers.set("Content-Type", "text/html; charset=UTF-8");

  return new Response(html, {
    status: originalResponse.status,
    statusText: originalResponse.statusText,
    headers,
  });
}

function lockedRevisionButton(pathname) {
  const safePath = escapeHtml(pathname);

  return `<a
    class="ctrl-btn secondary"
    id="btn-ccf"
    href="${safePath}?deverrouiller=1"
    style="text-decoration:none;display:inline-flex;align-items:center"
  >🔒 Afficher le CCF</a>`;
}

function lockedBpButton(pathname) {
  const safePath = escapeHtml(pathname);

  return `<a
    class="action-btn"
    href="${safePath}?deverrouiller=1"
    style="text-decoration:none;background:#8e44ad;display:inline-flex;align-items:center"
  >🔒 Contrôle BP - 4 pages</a>`;
}

function removeRangeByMarkers(html, startRegex, endMarker, placeholder) {
  const startMatch = startRegex.exec(html);

  if (!startMatch || startMatch.index === undefined) {
    return html;
  }

  const endIndex = html.indexOf(endMarker, startMatch.index);

  if (endIndex === -1) {
    return html;
  }

  return (
    html.slice(0, startMatch.index) +
    placeholder +
    html.slice(endIndex)
  );
}

function stripRevisionCcf(html, pathname) {
  let transformed = html.replace(
    /<button\b(?=[^>]*\bid=["']btn-ccf["'])[^>]*>[\s\S]*?<\/button>/i,
    lockedRevisionButton(pathname),
  );

  transformed = removeRangeByMarkers(
    transformed,
    /<div\b(?=[^>]*\bid=["']ccf["'])(?=[^>]*\bclass=["'][^"']*\bdoc\b[^"']*["'])[^>]*>/i,
    "<script>",
    '<div id="ccf" class="doc" hidden></div>\n',
  );

  return transformed;
}

function stripBpControl(html, pathname) {
  let transformed = html.replace(
    /<button\b(?=[^>]*\bdata-target=["']controle["'])[^>]*>[\s\S]*?<\/button>/i,
    lockedBpButton(pathname),
  );

  transformed = removeRangeByMarkers(
    transformed,
    /<section\b(?=[^>]*\bid=["']controle["'])(?=[^>]*\bclass=["'][^"']*\bsection\b[^"']*["'])[^>]*>/i,
    "<script>",
    '<section class="section" id="controle" hidden></section>\n',
  );

  return transformed;
}

function injectBeforeBody(html, snippet) {
  const bodyEnd = html.lastIndexOf("</body>");

  if (bodyEnd === -1) {
    return `${html}${snippet}`;
  }

  return `${html.slice(0, bodyEnd)}${snippet}${html.slice(bodyEnd)}`;
}

function injectUnlockButton(html, pathname) {
  const safePath = escapeHtml(pathname);

  const snippet = `
<style id="cfa-control-lock-style">
  #cfa-control-lock-button {
    position: fixed;
    right: 14px;
    bottom: 14px;
    z-index: 2147483647;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 9px 12px;
    color: #20242a;
    background: #f5c400;
    border: 2px solid #20242a;
    border-radius: 9px;
    box-shadow: 0 5px 16px rgba(0, 0, 0, 0.2);
    font: 800 12px/1 Arial, Helvetica, sans-serif;
    text-decoration: none;
  }

  #cfa-control-lock-button:hover {
    background: #ffd52e;
  }

  @media print {
    #cfa-control-lock-button {
      display: none !important;
    }
  }
</style>
<a id="cfa-control-lock-button" href="${safePath}?verrouiller=1">
  🔒 Verrouiller
</a>`;

  return injectBeforeBody(html, snippet);
}

function injectOpenControlScript(html, mode) {
  let action = "";

  if (mode === "revision-ccf2") {
    action = `
      if (typeof window.showDoc === "function") {
        window.showDoc("ccf");
      }
    `;
  }

  if (mode === "bp-ondes") {
    action = `
      const controlButton = document.querySelector('[data-target="controle"]');

      if (controlButton) {
        controlButton.click();
      }
    `;
  }

  if (!action) {
    return html;
  }

  const snippet = `
<script id="cfa-open-control-script">
  window.addEventListener("DOMContentLoaded", () => {
    ${action}
    window.history.replaceState({}, "", window.location.pathname);
  });
</script>`;

  return injectBeforeBody(html, snippet);
}

async function authenticatedPage(request, context, mode, shouldOpenControl) {
  const originResponse = await context.next();
  const contentType = originResponse.headers.get("content-type") ?? "";

  if (!contentType.includes("text/html")) {
    const headers = noStoreHeaders(originResponse.headers);

    return new Response(originResponse.body, {
      status: originResponse.status,
      statusText: originResponse.statusText,
      headers,
    });
  }

  let html = await originResponse.text();

  if (shouldOpenControl && mode) {
    html = injectOpenControlScript(html, mode);
  }

  html = injectUnlockButton(html, new URL(request.url).pathname);

  return responseWithHtml(html, originResponse);
}

async function publicMixedPage(request, context, mode) {
  const originResponse = await context.next();
  const contentType = originResponse.headers.get("content-type") ?? "";

  if (!contentType.includes("text/html")) {
    return originResponse;
  }

  const pathname = new URL(request.url).pathname;
  let html = await originResponse.text();

  if (mode === "revision-ccf2") {
    html = stripRevisionCcf(html, pathname);
  }

  if (mode === "bp-ondes") {
    html = stripBpControl(html, pathname);
  }

  return responseWithHtml(html, originResponse);
}

export default async function protectionControles(request, context) {
  const url = new URL(request.url);
  const normalizedPath = normalizePath(url.pathname);
  const mode = MIXED_PAGE_MODES.get(normalizedPath) ?? "";
  const isMixedPage = Boolean(mode);
  const isFullPage = FULL_PAGE_PATHS.has(normalizedPath);

  const password = Netlify.env.get("CONTROL_PASSWORD");
  const sessionSecret = Netlify.env.get("CONTROL_SESSION_SECRET");

  /*
    Si la fonction est appelée sur un chemin non prévu, on laisse passer.
  */
  if (!isFullPage && !isMixedPage) {
    return context.next();
  }

  /*
    Sans configuration privée dans Netlify, l'accès sensible reste bloqué.
  */
  if (!password || !sessionSecret) {
    if (isMixedPage && request.method === "GET" && !url.searchParams.has("deverrouiller")) {
      return publicMixedPage(request, context, mode);
    }

    return new Response(configurationErrorPage(), {
      status: 503,
      headers: {
        "Content-Type": "text/html; charset=UTF-8",
        "Cache-Control": "no-store",
      },
    });
  }

  /*
    Bouton permettant de refermer les contrôles sur l'ordinateur utilisé.
  */
  if (url.searchParams.get("verrouiller") === "1") {
    return redirectResponse(url.pathname, expiredCookieHeader());
  }

  const cookieValue = context.cookies.get(COOKIE_NAME);
  const hasValidSession = await sessionIsValid(cookieValue, sessionSecret);

  if (hasValidSession) {
    const shouldOpenControl = url.searchParams.get("ouvrir") === "controle";

    return authenticatedPage(
      request,
      context,
      mode,
      shouldOpenControl,
    );
  }

  /*
    Dans une page mixte, les révisions sont servies publiquement.
    Le contrôle est retiré de la réponse HTML.
  */
  const wantsToUnlock =
    url.searchParams.get("deverrouiller") === "1" ||
    url.searchParams.get("ouvrir") === "controle";

  if (
    isMixedPage &&
    request.method !== "POST" &&
    !wantsToUnlock
  ) {
    return publicMixedPage(request, context, mode);
  }

  /*
    Validation du formulaire de mot de passe.
  */
  if (request.method === "POST") {
    let submittedPassword = "";

    try {
      const formData = await request.formData();
      submittedPassword = String(formData.get("password") ?? "");
    } catch {
      submittedPassword = "";
    }

    if (await passwordMatches(submittedPassword, password)) {
      const sessionValue = await createSessionValue(sessionSecret);
      const destination = isMixedPage
        ? `${url.pathname}?ouvrir=controle`
        : url.pathname;

      return redirectResponse(
        destination,
        sessionCookieHeader(sessionValue),
      );
    }

    return new Response(
      loginPage(url.pathname, isMixedPage, "Mot de passe incorrect."),
      {
        status: 401,
        headers: {
          "Content-Type": "text/html; charset=UTF-8",
          "Cache-Control": "no-store",
          "X-Robots-Tag": "noindex, nofollow",
        },
      },
    );
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Méthode non autorisée", {
      status: 405,
      headers: {
        Allow: "GET, HEAD, POST",
        "Cache-Control": "no-store",
      },
    });
  }

  return new Response(loginPage(url.pathname, isMixedPage), {
    status: 401,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

/*
  La fonction est déclarée sur tous les chemins avec /*.
  Elle laisse immédiatement passer les fichiers non concernés.
  Cela évite les erreurs URLPattern provoquées par les caractères + et &
  présents dans certains noms de fichiers.
*/
export const config = {
  method: ["GET", "POST"],
  path: "/*",
};
