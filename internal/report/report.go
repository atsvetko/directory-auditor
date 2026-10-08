// Package report renders a check.Result as JSON and as a self-contained HTML
// page (no external assets). The HTML here is a skeleton; the shared design
// system with the web wizard arrives with milestone K4.
package report

import (
	"encoding/json"
	"html/template"
	"io"

	"github.com/atsvetko/directory-auditor/internal/check"
)

// WriteJSON writes the stable machine-readable form.
func WriteJSON(w io.Writer, r *check.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteHTML writes a self-contained page. All directory-sourced strings pass
// through html/template's contextual escaping — object names, descriptions and
// DNS records are attacker-controllable data (approach §2.1).
func WriteHTML(w io.Writer, r *check.Result, lang string) error {
	if lang != "ru" {
		lang = "en"
	}
	return page.Execute(w, map[string]any{"R": r, "Lang": lang, "Sev": check.SortedSeverities(r.Counts)})
}

var page = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="{{.Lang}}">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
<title>Directory Auditor — {{.R.Target}}</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#1b1f24;background:#fff}
  h1{color:#0f4c81;margin:0 0 4px} .muted{color:#5a6270;font-size:13px}
  .score{font-size:40px;font-weight:800;color:#0f4c81}
  .grid{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:12px;margin:16px 0}
  .k{background:#eef4fa;border-left:4px solid #0f4c81;padding:8px 12px} .k b{display:block;font-size:20px}
  table{border-collapse:collapse;width:100%;font-size:14px;table-layout:fixed} th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #dfe5ec;vertical-align:top;overflow-wrap:anywhere}
  td.id{white-space:nowrap} td.ev code{overflow-wrap:anywhere}
  th{color:#5a6270;font-size:12px;text-transform:uppercase}
  .fail{color:#a33;font-weight:700} .pass{color:#1f7a3f;font-weight:700} .skip{color:#8a94a3}
  .banner{background:#fff4e5;border:1px solid #f0c36d;padding:8px 12px;margin:12px 0;font-size:14px}
  .preview{background:#eef4fa;border:1px solid #9fbbd8;padding:8px 12px;margin:12px 0;font-size:14px}
  .tag{display:inline-block;font-size:11px;line-height:16px;padding:0 5px;border-radius:3px;background:#dde8f3;color:#0f4c81;margin-left:6px;vertical-align:middle}
  td.id .tag{display:block;margin:3px 0 0;width:max-content}
  code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
</style>
</head>
<body>
<h1>Directory Auditor</h1>
<div class="muted">{{if eq .Lang "ru"}}Цель{{else}}Target{{end}}: <code>{{.R.Target}}</code> · {{.R.Provider}}{{if .R.Dialect}}/{{.R.Dialect}}{{end}} · {{if eq .Lang "ru"}}уровень{{else}}tier{{end}} {{.R.Tier}} · {{.R.AnalysedAt.Format "2006-01-02 15:04 UTC"}} · {{if eq .Lang "ru"}}снимок{{else}}snapshot{{end}} <code>{{printf "%.16s" .R.SnapshotHash}}…</code></div>
{{if .R.Unsigned}}<div class="banner">{{if eq .Lang "ru"}}Внимание: загружены неподписанные пакеты проверок (режим разработки).{{else}}Warning: unsigned check packs were loaded (development mode).{{end}}</div>{{end}}
{{if .R.Preview}}<div class="preview">{{if eq .Lang "ru"}}<b>Предварительные проверки:</b> {{.R.Preview}} записей каталога оценены как проверки. Они не подписаны и ещё не проверены человеком (статус «черновик»); в таблице отмечены как <span class="tag">preview</span>. Считайте их находки поводом для проверки, а не подтверждённым результатом.{{else}}<b>Preview checks:</b> {{.R.Preview}} catalogue entries were evaluated as checks. They are unsigned and not yet verified by a human (status draft); the table marks them <span class="tag">preview</span>. Treat their findings as leads to confirm, not as verified results.{{end}}</div>{{end}}
<div class="score">{{.R.Score}} / 100</div>
<div class="grid">
  <div class="k"><b>{{.R.Counts.Checked}}</b>{{if eq .Lang "ru"}}проверено{{else}}checked{{end}}</div>
  <div class="k"><b>{{.R.Counts.Passed}}</b>{{if eq .Lang "ru"}}пройдено{{else}}passed{{end}}</div>
  <div class="k"><b>{{.R.Counts.Failed}}</b>{{if eq .Lang "ru"}}с находками{{else}}with findings{{end}}</div>
  <div class="k"><b>{{.R.Counts.Findings}}</b>{{if eq .Lang "ru"}}находок{{else}}findings{{end}}</div>
  <div class="k"><b>{{.R.Counts.Skipped}}</b>{{if eq .Lang "ru"}}пропущено{{else}}skipped{{end}}</div>
</div>
<table>
<colgroup><col style="width:7.5em"><col><col style="width:9em"><col style="width:5.5em"><col style="width:8.5em"><col style="width:8em"><col style="width:6em"></colgroup>
<tr><th>ID</th><th>{{if eq .Lang "ru"}}Проверка{{else}}Check{{end}}</th><th>{{if eq .Lang "ru"}}Область{{else}}Domain{{end}}</th><th>{{if eq .Lang "ru"}}Уровень{{else}}Tier{{end}}</th><th>{{if eq .Lang "ru"}}Серьёзность{{else}}Severity{{end}}</th><th>{{if eq .Lang "ru"}}Статус{{else}}Status{{end}}</th><th>{{if eq .Lang "ru"}}Объекты{{else}}Objects{{end}}</th></tr>
{{range .R.Checks}}<tr>
  <td class="id"><code>{{.ID}}</code>{{if .Preview}}<span class="tag">preview</span>{{end}}</td>
  <td>{{if eq $.Lang "ru"}}{{.Title.RU}}{{else}}{{.Title.EN}}{{end}}</td>
  <td>{{.Domain}}</td><td>{{.Tier}}</td><td>{{.Severity}}</td>
  <td class="{{if eq .Status "fail"}}fail{{else if eq .Status "pass"}}pass{{else}}skip{{end}}">{{.Status}}{{if .Skip}} ({{.Skip}}){{end}}</td>
  <td>{{.Matched}}{{if .Findings}} / {{len .Findings}}{{end}}</td>
</tr>
{{range .Findings}}<tr><td></td><td class="ev" colspan="6"><code>{{.DN}}</code>{{range $k, $v := .Evidence}} · {{$k}}=<code>{{$v}}</code>{{end}}</td></tr>{{end}}
{{end}}
</table>
<p class="muted">{{if eq .Lang "ru"}}Отчёт создан в режиме «только чтение»; ничего не покидало эту машину.{{else}}Generated read-only; nothing left this machine.{{end}}</p>
</body>
</html>
`))
