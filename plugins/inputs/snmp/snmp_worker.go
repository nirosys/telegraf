package snmp

import (
	"sync"
)

type jobQueue chan snmpConnection
type resultQueue chan workerResult

// workerResult represents the outcome of work done by one of the workers.
type workerResult struct {
	// Err contains the error that occurred during SNMP processing, if unsuccessful.
	Err error
	// Result contains a pointer to the RTable generated for a single Table get.
	Result *RTable
}

type snmpWorker struct {
	jobs    jobQueue
	results resultQueue
	wg      *sync.WaitGroup
}

func (w *snmpWorker) Gather(name string, fields []Field, tables []Table) {
	defer w.wg.Done()
	for conn := range w.jobs {
		// First is the top-level fields. We treat the fields as table prefixes with an empty index.
		t := Table{
			Name:   name,
			Fields: fields,
		}
		topTags := map[string]string{}

		if rt, err := gatherTable(conn, t, topTags, false); err != nil {
			w.registerError(Errorf(err, "agent %s", conn.Host()))
		} else {
			w.registerData(rt)
		}

		// Now is the real tables.
		for _, t := range tables {
			if rt, err := gatherTable(conn, t, topTags, true); err != nil {
				w.registerError(Errorf(err, "agent: %s: gathering table %s", conn.Host(), t.Name))
			} else {
				w.registerData(rt)
			}
		}
	}
}

func (w *snmpWorker) registerData(r *RTable) {
	w.results <- workerResult{Result: r}
}

func (w *snmpWorker) registerError(err error) {
	w.results <- workerResult{Err: err}
}

// IsError is a convenience function for testing whether or not a workerResult
// is an error.
func (wr *workerResult) IsError() bool {
	return (wr.Err != nil)
}

func gatherTable(gs snmpConnection, t Table, topTags map[string]string, walk bool) (*RTable, error) {
	rt, err := t.Build(gs, walk)
	if err != nil {
		return nil, err
	}

	for _, tr := range rt.Rows {
		if !walk {
			// top-level table. Add tags to topTags.
			for k, v := range tr.Tags {
				topTags[k] = v
			}
		} else {
			// real table. Inherit any specified tags.
			for _, k := range t.InheritTags {
				if v, ok := topTags[k]; ok {
					tr.Tags[k] = v
				}
			}
		}
		if _, ok := tr.Tags["agent_host"]; !ok {
			tr.Tags["agent_host"] = gs.Host()
		}
	}

	return rt, err
}
