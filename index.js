'use strict';

const http = require('http');
const https = require('https');
const axios = require('axios');
const {JSDOM} = require('jsdom');

const PORT = 3003;

// Reuse TCP connections to avoid ETIMEDOUT from rate-limiting on new connections
const httpsAgent = new https.Agent({keepAlive: true, maxSockets: 5});
const httpAgent = new http.Agent({keepAlive: true, maxSockets: 5});

// Global attributes allowed on every element (mirrors Oro's @[id|style|class])
const GLOBAL_ATTRS = ['id', 'style', 'class'];

// Default whitelist derived from Oro's HTMLPurifier "lax" scope (default + lax extensions).
// Keys are tag names (lowercase), values are arrays of allowed attribute names
// beyond the global set. A tag with null means only global attrs are allowed.
const DEFAULT_WHITELIST = {
    iframe: ['allowfullscreen', 'frameborder', 'height', 'marginheight', 'marginwidth', 'name', 'scrolling', 'src', 'width', 'allow', 'title'],
    table: ['cellspacing', 'cellpadding', 'border', 'align', 'width'],
    thead: ['align', 'valign'],
    tbody: ['align', 'valign'],
    tr: ['align', 'valign'],
    td: ['align', 'valign', 'rowspan', 'colspan', 'bgcolor', 'nowrap', 'width', 'height'],
    th: ['align', 'valign', 'rowspan', 'colspan', 'bgcolor', 'nowrap', 'width', 'height', 'scope'],
    a: ['href', 'data-yt-id', 'target', 'title', 'data-action', 'tabindex', 'data-toggle', 'data-slide', 'data-trigger', 'aria-label', 'aria-disabled', 'aria-expanded', 'aria-controls', 'aria-haspopup', 'aria-selected', 'data-content', 'data-placement'],
    div: ['data-title', 'data-type', 'data-bg', 'data-href', 'aria-label', 'aria-labelledby', 'aria-orientation', 'aria-valuenow', 'aria-valuemin', 'aria-valuemax', 'aria-live', 'aria-atomic', 'data-spy', 'data-ride', 'data-interval', 'data-parent', 'data-target', 'data-offset', 'data-delay', 'data-autohide', 'tabindex', 'aria-hidden'],
    button: ['type', 'title', 'aria-label', 'aria-haspopup', 'aria-expanded', 'aria-labelledby', 'aria-controls', 'data-dismiss', 'data-toggle', 'data-target', 'data-display', 'data-content', 'data-container', 'data-placement', 'disabled'],
    span: ['data-title', 'data-type', 'title', 'aria-hidden', 'data-toggle', 'data-content', 'tabindex'],
    nav: ['aria-label'],
    ul: ['type'],
    ol: ['type'],
    li: ['aria-current', 'aria-selected', 'data-target', 'data-slide-to'],
    cite: ['title'],
    img: ['src', 'srcset', 'width', 'height', 'alt', 'loading'],
    blockquote: ['cite'],
    font: ['color'],
    br: [],
    source: ['srcset', 'type', 'media', 'sizes'],
    time: ['datetime'],
    video: ['allowfullscreen', 'autoplay', 'loop', 'poster', 'src', 'controls'],
    // Elements with only global attrs
    dl: [], dt: [], dd: [], em: [], strong: [], b: [], p: [], u: [], i: [],
    h1: [], h2: [], h3: [], h4: [], h5: [], h6: [], hgroup: [],
    abbr: [], address: [], article: [], audio: [], bdo: [], caption: [],
    code: [], col: [], colgroup: [], del: [], details: [], dfn: [],
    figure: [], figcaption: [], picture: [], footer: [], header: [], hr: [],
    ins: [], kbd: [], mark: [], menu: [], pre: [], q: [], samp: [],
    section: [], small: [], strike: [], sub: [], sup: [], tfoot: [],
    var: [], aside: [],
};

function readBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        req.on('error', reject);
    });
}

function sendJson(res, status, data) {
    const body = JSON.stringify(data);
    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
    });
    res.end(body);
}

function buildWhitelist(override) {
    if (!override) {
        return DEFAULT_WHITELIST;
    }
    const merged = {...DEFAULT_WHITELIST};
    for (const [tag, attrs] of Object.entries(override)) {
        merged[tag.toLowerCase()] = Array.isArray(attrs) ? attrs : [];
    }
    return merged;
}

/**
 * Convert onclick="window.location.href='...'" to data-href before sanitization
 * strips the onclick attribute. Downstream PHP processors convert these into <a> tags.
 */
function convertOnclickToDataHref(document) {
    const elements = document.querySelectorAll('[onclick]');
    for (const el of elements) {
        const onclick = el.getAttribute('onclick');
        const match = onclick.match(/window\.location\.href\s*=\s*['"]([^'"]+)['"]/);
        if (match) {
            el.setAttribute('data-href', match[1]);
        }
    }
}

function sanitizeAttributes(document, whitelist) {
    const violations = [];
    const allElements = document.querySelectorAll('*');

    for (const el of allElements) {
        const tag = el.tagName.toLowerCase();
        const allowedForTag = whitelist[tag];
        const allowed = allowedForTag
            ? new Set([...GLOBAL_ATTRS, ...allowedForTag])
            : new Set(GLOBAL_ATTRS);

        const toRemove = [];
        for (const attr of el.attributes) {
            if (/[<>]/.test(attr.value)) {
                const original = attr.value;
                attr.value = attr.value.replace(/[<>]/g, '');
                violations.push({
                    tag,
                    attribute: attr.name,
                    issue: 'invalid_chars',
                    original,
                    fixed: attr.value
                });
            }

            if (!allowed.has(attr.name)) {
                toRemove.push(attr.name);
                violations.push({
                    tag,
                    attribute: attr.name,
                    issue: 'not_allowed',
                    value: attr.value.substring(0, 100)
                });
            }
        }

        for (const name of toRemove) {
            el.removeAttribute(name);
        }
    }

    return violations;
}

/**
 * Strip HTML tags (e.g. <p>, <br />) that appear as literal text inside <style>
 * elements. Some CMS editors inject markup into CSS blocks.
 */
function sanitizeStyleElements(document, violations) {
    const styleNodes = document.querySelectorAll('style');
    for (const style of styleNodes) {
        const original = style.textContent;
        const cleaned = original.replace(/<\/?[a-zA-Z][^>]*\/?>/g, '');
        if (cleaned !== original) {
            style.textContent = cleaned;
            violations.push({
                tag: 'style',
                issue: 'html_in_css',
                message: 'Removed HTML tags from <style> element content'
            });
        }
    }
}

function fetchUrl(url, retries = 3) {
    return axios.get(url, {
        responseType: 'arraybuffer',
        maxRedirects: 10,
        timeout: 30000,
        httpAgent,
        httpsAgent,
        headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; html-repair/1.0)'
        }
    }).catch(async (err) => {
        if (retries > 0 && (!err.response || err.response.status >= 500)) {
            const delay = (4 - retries) * 3000;
            console.warn(`Retry ${4 - retries}/3 for ${url} after ${delay}ms (${err.code || err.message})`);
            await new Promise(r => setTimeout(r, delay));
            return fetchUrl(url, retries - 1);
        }
        throw err;
    });
}

function repairHtml(data, contentType, allowedAttributes) {
    // Pre-process: decode to string and restore closing tags that were accidentally
    // wrapped in HTML comments (e.g. <!-- </div> -->). Some CMS pages have this pattern
    // where a closing tag is commented out, leaving its parent element unclosed.
    // JSDOM/parse5 treats comments as no-ops, so it would nest subsequent siblings
    // inside the unclosed parent instead of placing them correctly.
    const raw = Buffer.from(data).toString('utf8');
    const preProcessed = raw.replace(/<!--\s*(<\/[a-zA-Z][^>]*>)\s*-->/g, '$1');

    // JSDOM uses parse5 (HTML5 spec) which auto-closes remaining unclosed tags,
    // fixes invalid nesting (e.g. <p> containing block elements), and
    // normalizes the document structure.
    const dom = new JSDOM(preProcessed, {contentType});
    const document = dom.window.document;
    const violations = [];

    // Clean HTML tags from inside <style> elements (e.g. <p>, <br /> injected by CMS editors)
    sanitizeStyleElements(document, violations);

    // Preserve onclick navigation URLs as data-href before sanitization removes onclick
    convertOnclickToDataHref(document);

    const whitelist = buildWhitelist(allowedAttributes);
    violations.push(...sanitizeAttributes(document, whitelist));

    const title = document.querySelector('title')?.textContent?.trim() || null;

    // Extract body innerHTML only — avoids <html>/<head>/<body> wrappers
    // that cause issues when downstream PHP re-parses with LIBXML_HTML_NOIMPLIED
    const html = document.body ? document.body.outerHTML : dom.serialize();

    return {html, title, violations};
}

const server = http.createServer(async (req, res) => {
    if (req.method !== 'POST' || req.url !== '/repair') {
        return sendJson(res, 404, {error: 'Not found. Use POST /repair with { "url": "..." }'});
    }

    let body;
    try {
        body = await readBody(req);
    } catch (err) {
        return sendJson(res, 400, {error: 'Failed to read request body'});
    }

    let url, allowedAttributes;
    try {
        ({url, allowedAttributes} = JSON.parse(body));
    } catch {
        return sendJson(res, 400, {error: 'Invalid JSON body'});
    }

    if (!url || typeof url !== 'string') {
        return sendJson(res, 400, {error: 'Missing or invalid "url" field'});
    }

    let response;
    try {
        response = await fetchUrl(url);
    } catch (err) {
        const status = err.response ? err.response.status : 502;
        return sendJson(res, status, {error: `Failed to fetch URL: ${err.message}`});
    }

    const contentType = response.headers['content-type'] || 'text/html';
    const result = repairHtml(response.data, contentType, allowedAttributes);

    const resultBody = JSON.stringify(result);
    res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(resultBody)
    });
    res.end(resultBody);
});

server.listen(PORT, () => {
    console.log(`HTML repair service listening on http://localhost:${PORT}`);
    console.log('Usage: POST /repair  body: { "url": "...", "allowedAttributes": {...} }');
});
