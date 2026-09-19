package notification

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type TelegramUpdateStore interface {
	Process(context.Context, int, func() (TelegramReply, error)) (TelegramReply, error)
}

type SQLTelegramUpdateStore struct{ DB *sql.DB }

func (s SQLTelegramUpdateStore) Process(ctx context.Context, updateID int, fn func() (TelegramReply, error)) (TelegramReply, error) {
	if s.DB == nil || updateID == 0 || fn == nil {
		return TelegramReply{}, errors.New("valid Telegram update store request required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return TelegramReply{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(updateID)); err != nil {
		return TelegramReply{}, err
	}
	var raw string
	var denied bool
	err = tx.QueryRowContext(ctx, `SELECT reply_json, denied FROM notification_telegram_updates WHERE update_id=$1`, updateID).Scan(&raw, &denied)
	if err == nil {
		var reply TelegramReply
		if json.Unmarshal([]byte(raw), &reply) != nil {
			return TelegramReply{}, errors.New("stored Telegram update reply invalid")
		}
		if err := tx.Commit(); err != nil {
			return TelegramReply{}, err
		}
		if denied {
			return reply, errors.New("Telegram update denied")
		}
		return reply, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return TelegramReply{}, err
	}
	reply, processErr := fn()
	encoded, err := json.Marshal(reply)
	if err != nil {
		return TelegramReply{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO notification_telegram_updates(update_id, reply_json, denied, processed_at) VALUES ($1,$2,$3,$4)`, updateID, string(encoded), processErr != nil, time.Now().UTC()); err != nil {
		return TelegramReply{}, err
	}
	if err := tx.Commit(); err != nil {
		return TelegramReply{}, err
	}
	return reply, processErr
}
