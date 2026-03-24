'use strict';

const http = require('http');
const axios = require('axios');
const {JSDOM} = require('jsdom');

const PORT = 3003;

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
    a: ['href', 'target', 'title', 'data-action', 'tabindex', 'role', 'data-toggle', 'data-slide', 'data-trigger', 'aria-label', 'aria-disabled', 'aria-expanded', 'aria-controls', 'aria-haspopup', 'aria-selected', 'data-content', 'data-placement'],
    div: ['data-title', 'data-type', 'role', 'aria-label', 'aria-labelledby', 'aria-orientation', 'aria-valuenow', 'aria-valuemin', 'aria-valuemax', 'aria-live', 'aria-atomic', 'data-spy', 'data-ride', 'data-interval', 'data-parent', 'data-target', 'data-offset', 'data-delay', 'data-autohide', 'tabindex', 'aria-hidden'],
    button: ['type', 'title', 'aria-label', 'aria-haspopup', 'aria-expanded', 'aria-labelledby', 'aria-controls', 'data-dismiss', 'data-toggle', 'data-target', 'data-display', 'data-content', 'data-container', 'data-placement', 'disabled'],
    span: ['data-title', 'data-type', 'title', 'role', 'aria-hidden', 'data-toggle', 'data-content', 'tabindex'],
    nav: ['aria-label'],
    ul: ['type', 'role'],
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
            // Sanitize invalid characters in attribute values
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

            // Remove attributes not in whitelist
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

    let html;
    try {
        const response = await axios.get(url, {
            responseType: 'text',
            maxRedirects: 10,
            headers: {
                'User-Agent': 'Mozilla/5.0 (compatible; html-repair/1.0)'
            }
        });
        html = response.data;
    } catch (err) {
        const status = err.response ? err.response.status : 502;
        return sendJson(res, status, {error: `Failed to fetch URL: ${err.message}`});
    }

    // jsdom uses the same HTML5 parsing algorithm as browsers (parse5),
    // which automatically repairs malformed markup (unclosed tags, etc.)
    const dom = new JSDOM(html);
    const whitelist = buildWhitelist(allowedAttributes);
    const violations = sanitizeAttributes(dom.window.document, whitelist);

    const repaired = dom.serialize();

    const result = {
        html: repaired,
        violations
    };

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
