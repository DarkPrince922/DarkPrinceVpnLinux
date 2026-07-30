package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenGeneratesStableHWID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("состояние не создалось: %v", err)
	}
	hwid := first.Snapshot().HWID
	if hwid == "" {
		t.Fatal("HWID не сгенерирован")
	}

	// перезапуск не должен менять идентификатор: иначе панель считала бы
	// каждый запуск новым устройством и съедала лимит тарифа
	second, err := Open(path)
	if err != nil {
		t.Fatalf("состояние не перечиталось: %v", err)
	}
	if got := second.Snapshot().HWID; got != hwid {
		t.Errorf("HWID сменился: было %q, стало %q", hwid, got)
	}
}

func TestStateFileKeepsTokensPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *State) { s.RefreshToken = "секрет" }); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("права на файл с токенами = %o, ожидались 600", mode)
	}
}

func TestSnapshotIsIsolatedFromStore(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *State) { s.SetSubscriptionBody(nil, "первая") }); err != nil {
		t.Fatal(err)
	}

	// правка копии не должна протекать обратно в хранилище
	snapshot := st.Snapshot()
	snapshot.Subscriptions["default"] = "подменено"

	if got := st.Snapshot().SubscriptionBody(nil); got != "первая" {
		t.Errorf("копия протекла в хранилище: %q", got)
	}
}

func TestPerSubscriptionDataIsSeparate(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, second := int64(1), int64(2)

	err = st.Update(func(s *State) {
		s.SetSubscriptionBody(&first, "узлы-1")
		s.SetSubscriptionBody(&second, "узлы-2")
		s.SetServerIndex(&first, 3)
		s.SetServerIndex(&second, 7)
	})
	if err != nil {
		t.Fatal(err)
	}

	state := st.Snapshot()
	if state.SubscriptionBody(&first) != "узлы-1" || state.SubscriptionBody(&second) != "узлы-2" {
		t.Error("подписки перепутались телами")
	}
	if state.ServerIndex(&first) != 3 || state.ServerIndex(&second) != 7 {
		t.Error("подписки перепутались выбранными узлами")
	}
	// подписка без id не должна пересекаться с нумерованными
	if state.SubscriptionBody(nil) != "" {
		t.Error("общий ключ подхватил чужие данные")
	}
}

// Оборванная запись не должна оставить пользователя без токенов.
func TestSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *State) { s.RefreshToken = "живой" }); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tmp" {
			t.Errorf("после записи остался временный файл %s", entry.Name())
		}
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("состояние не перечиталось: %v", err)
	}
	if reopened.Snapshot().RefreshToken != "живой" {
		t.Error("токен не сохранился")
	}
}
