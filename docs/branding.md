# White-label branding

An administrator can make the portal look like the customer's own product: **Users tab → Branding**.

| Setting | Effect |
|---|---|
| Product name | Browser tab title, header, sign-in page, printed report. Up to 40 characters. |
| Accent colour | Buttons, selected tabs, charts, report headings. Text on it turns black or white automatically for legibility. "Use default blue" resets it. |
| Default theme | **Auto** follows the device's light/dark setting, **Day** and **Night** force one. It applies to people who have not picked a theme themselves; the ◐/☀/☾ button in the header always overrides it for that browser. |
| Default language | The language of the console for people who have not chosen one (see below). |
| Sign-in message | Replaces the tagline under the name on the sign-in page (up to 300 characters). |
| Logo | PNG, JPEG, GIF or WebP, at most 256 KB. Shown in the header, on the sign-in page and on the printed report. |

## Languages

The console speaks **English, German (Deutsch), French (Français), Spanish (Español) and Slovak (Slovenčina)**.
English is the default. Everyone can change the language with the picker in the header (or on the sign-in page);
the choice is remembered in that browser. An administrator sets the **default language** under *Users → Branding*:
it applies to people who have not picked one. The built-in documentation follows the console's language for its
menu and header; the pages themselves are English.

What is translated: every menu, button, label, dialog, message, the detection rules and their settings, findings
and what to do about them, the advice shown with alerts, the compliance view, and the device types and icon names.
What is not: the text of an alert itself (for example "Entrance camera contacted known-bad address …") and its
"why this score" lines, because they are recorded in English when the alert is raised and stay that way in the
database, the audit log and what is sent to Slack, e-mail or a SIEM; names you type; and the API's error
messages, of which the common ones are translated in the console. Dates and numbers follow the language.

## Things worth knowing

* **SVG logos are refused.** An SVG can contain script and the logo is served from the portal's own address,
  so only real raster images are accepted. The file type is decided from the file's content, not its name.
* Branding is **readable without signing in** (the sign-in page needs it) and contains nothing but the items
  above. Only administrators can change it, and every change is written to the audit log.
* All values are displayed as plain text, never as HTML.
* A very light accent colour on the night theme (or a very dark one on the day theme) can be hard to read;
  choose a mid-tone colour if you allow both.
* API: `GET /api/branding` (public), `PUT /api/branding` (admin, JSON), `PUT|DELETE /api/branding/logo`
  (admin, raw image body). See the [API reference](api.md).
