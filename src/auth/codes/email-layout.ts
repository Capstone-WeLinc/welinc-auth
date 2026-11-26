import {
  EMAIL_LOGO_HEIGHT,
  EMAIL_LOGO_PNG_BASE64,
  EMAIL_LOGO_WIDTH,
} from './email-logo';

// Suite spec 0019, AC-27: the one branded layout every code email shares (setup, reset, sign in,
// email change), from the Round 34 reset email: the ///L mark on a navy header, the code large in
// a monospace font, a footer, and a plain text part with the same content. Tables and inline
// styles only, so Gmail and Outlook draw it the same. The logo is a PNG sent as a CID attachment:
// never SVG, a data URI or a remote image (no link, no tracking pixel; suite spec 0009, AC-34).

/** The `cid` the logo attachment and the `<img>` share. */
export const EMAIL_LOGO_CID = 'welinc-logo@welinc.app';

export type EmailAttachment = {
  filename: string;
  content: Buffer;
  contentType: string;
  cid: string;
};

export const FOOTER_BRAND = 'WeLinc Logistics · Since 2018';
export const FOOTER_REASON =
  'You got this email because of a request on your WeLinc work account.';

const FONT = "Inter, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
const MONO = "'IBM Plex Mono', Menlo, Consolas, 'Courier New', monospace";

/** The logo attachment, built per email so no two sends share one buffer. */
export function logoAttachment(): EmailAttachment {
  return {
    filename: 'welinc-logo.png',
    content: Buffer.from(EMAIL_LOGO_PNG_BASE64, 'base64'),
    contentType: 'image/png',
    cid: EMAIL_LOGO_CID,
  };
}

/**
 * The branded HTML around one code. `before` and `after` are HTML paragraphs whose dynamic parts
 * the caller already escaped; `title` is plain text.
 */
export function codeEmailHtml(input: {
  title: string;
  before: string[];
  code: string;
  after: string[];
}): string {
  const lead = input.before
    .map(
      (p) =>
        `<p style="margin:12px 0 0;font-size:15px;line-height:1.6;color:#334155">${p}</p>`,
    )
    .join('\n');
  const tail = input.after
    .map(
      (p) =>
        `<p style="margin:0 0 10px;font-size:14px;line-height:1.6;color:#475569">${p}</p>`,
    )
    .join('\n');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${input.title}</title>
</head>
<body style="margin:0;padding:0;background:#e9ecf3">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#e9ecf3">
<tr><td align="center" style="padding:32px 12px">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;background:#ffffff;border-radius:14px;border-collapse:separate">
<tr><td style="background:#0f1445;padding:22px 36px;border-radius:14px 14px 0 0">
<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
<td style="padding-right:10px;vertical-align:middle"><img src="cid:${EMAIL_LOGO_CID}" width="${EMAIL_LOGO_WIDTH}" height="${EMAIL_LOGO_HEIGHT}" alt="WeLinc Logistics" style="display:block;border:0"></td>
<td style="vertical-align:middle;font-family:${FONT};font-size:16px;font-weight:800;font-style:italic;color:#ffffff">WeLinc Logistics</td>
</tr></table>
</td></tr>
<tr><td style="padding:36px 36px 28px;font-family:${FONT};color:#0f172a">
<h1 style="margin:0;font-size:24px;font-weight:800;color:#0f172a">${input.title}</h1>
${lead}
<p style="margin:26px 0"><span style="display:inline-block;padding:12px 18px;border-radius:10px;background:#f3f5f9;border:1px solid #dfe3ee;font-family:${MONO};font-size:30px;font-weight:700;letter-spacing:8px;color:#0f1445">${input.code}</span></p>
${tail}
</td></tr>
<tr><td style="padding:18px 36px;border-top:1px solid #eef1f6;font-family:${FONT};font-size:12.5px;line-height:1.6;color:#64748b">${FOOTER_BRAND}<br>${FOOTER_REASON}</td></tr>
</table>
</td></tr>
</table>
</body>
</html>`;
}

/** The plain text footer, matching the HTML one. */
export const TEXT_FOOTER = `--\n${FOOTER_BRAND}\n${FOOTER_REASON}`;
