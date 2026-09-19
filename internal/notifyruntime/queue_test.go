package notifyruntime

import (
	"context"

	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

type fakeQueueController struct {
	snapshot outboundpolicy.QueueSnapshot
	flushes  int
	retries  []string
	flushErr error
}

func (q *fakeQueueController) Snapshot(context.Context, string) (outboundpolicy.QueueSnapshot, error) {
	return q.snapshot, nil
}
func (q *fakeQueueController) Flush(context.Context) error {
	if q.flushErr != nil {
		err := q.flushErr
		q.flushErr = nil
		return err
	}
	q.flushes++
	return nil
}
func (q *fakeQueueController) Retry(_ context.Context, id string) error {
	q.retries = append(q.retries, id)
	return nil
}
