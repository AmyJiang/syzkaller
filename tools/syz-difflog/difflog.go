package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/google/syzkaller/diff"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
	"html/template"
	"net/http"
	"path/filepath"
	"strings"
)

type log struct {
	prog *prog.Prog
	rs   []*diff.ExecResult
}

type UIDiff struct {
	Log    string
	Name   string
	Deltas map[string]string
}

type UIDiffs struct {
	Filesystems []string
	Diffs       []*UIDiff
}

type UIDiffArray []*UIDiff

func (a UIDiffArray) Len() int           { return len(a) }
func (a UIDiffArray) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a UIDiffArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

var (
	flagDirs    = flag.String("dirs", "./logs", "log directories separated by ;")
	flagFS      = flag.String("testfs", "/testfs1:/testfs2", "testfs separated by :")
	flagHttp    = flag.String("http", ":9999", "TCP address to start http page")
	flagRetvals = flag.Bool("ret", true, "check return values for discrepancy")

	logs        map[string]*log
	filesystems []string
)

func readdirnames(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1)
}

func collectLogs(dir string) error {
	files, err := readdirnames(dir)
	if err != nil {
		return err
	}

	for _, fname := range files {
		if !strings.HasSuffix(fname, ".log") {
			continue
		}
		logf := filepath.Join(dir, fname)
		prog, _, rs, err := diff.ParseReproLog(logf, false, true)
		if err != nil {
			return fmt.Errorf("Failed to parse %v:%v", logf, err)
		}

		sig := strings.Split(fname, ".")[0]
		Logf(1, "Prog: %s", prog)
		if _, ok := logs[sig]; ok == false {
			logs[sig] = &log{
				prog: prog,
				rs:   []*diff.ExecResult{},
			}
		}
		logs[sig].rs = append(logs[sig].rs, rs...)
	}
	return nil
}

func httpDiff(w http.ResponseWriter, r *http.Request) {
	data := &UIDiffs{
		Filesystems: filesystems,
		Diffs:       []*UIDiff{},
	}

	var err error
	for sig := range logs {
		deltas := diff.Difference(logs[sig].rs, logs[sig].prog,
			[]string{"Name", "Mode", "Uid", "Size", "Link"}, // Dont test Gid for linux vs FreeBSD
			*flagRetvals)
		if !diff.HasDifference(deltas) {
			continue
		}

		data.Diffs = append(data.Diffs, &UIDiff{
			Log:    sig + ".log",
			Name:   logs[sig].prog.String(),
			Deltas: deltas,
		})
	}

	sort.Sort(UIDiffArray(data.Diffs))

	Logf(0, "Found %d Discrepancies", len(data.Diffs))

	if err != nil {
		http.Error(w, fmt.Sprintf("failed to collect diff logs: %v", err), http.StatusInternalServerError)
		return
	}
	if err := diffTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func main() {
	flag.Parse()
	if *flagDirs == "" {
		Fatalf("Must specify at least one log directory")
	}
	if *flagFS == "" {
		Fatalf("Must specify test filesystems")
	}

	logs = make(map[string]*log)
	dirs := strings.Split(*flagDirs, ";")
	filesystems = strings.Split(*flagFS, ":")

	for _, dir := range dirs {
		if err := collectLogs(dir); err != nil {
			Fatalf("Failed to collect logs in %v: %v", dir, err)
		}
	}

	Logf(0, "Collected %d logs in %d directories", len(logs), len(dirs))

	http.HandleFunc("/", httpDiff)

	Logf(0, "Serving on %s", *flagHttp)
	http.ListenAndServe(*flagHttp, nil)
}

func addStyle(html string) string {
	return strings.Replace(html, "{{STYLE}}", htmlStyle, -1)
}

const htmlStyle = `
	<style type="text/css" media="screen">
		table {
			border-collapse:collapse;
			border:1px solid;
		}
		table caption {
			font-weight: bold;
		}
		table td {
			border:1px solid;
			padding: 3px;
		}
		table th {
			border:1px solid;
			padding: 3px;
		}
		textarea {
			width:100%;
		}
	</style>
`

var diffTemplate = template.Must(template.New("").Parse(addStyle(`
<!doctype html>
<html>
<head>
	<title>Diffs</title>
	{{STYLE}}
</head>
<body>
<table>
	<tr>
		<th>Log</th>
        <th>Name</th>
        {{range $fs := $.Filesystems}}
        <th>{{$fs}}</th>
        {{end}}
	</tr>
	{{range $d := $.Diffs}}
	<tr>
		<td><a href="/file?name={{$d.Log}}">{{$d.Log}}</a></td>
        <td>{{$d.Name}}</td>
        {{range $fs := $.Filesystems}}
        <td>{{index $d.Deltas $fs}}</td>
		{{end}}
	</tr>
	{{end}}
</table>
</body></html>
`)))
