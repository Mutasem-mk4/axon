package evidence

import "sync"

type Interner struct {
	values sync.Map
}

func NewInterner() *Interner {
	return &Interner{}
}

func (i *Interner) Intern(value string) string {
	if i == nil || value == "" {
		return value
	}

	if interned, ok := i.values.Load(value); ok {
		return interned.(string)
	}

	interned, _ := i.values.LoadOrStore(value, value)
	return interned.(string)
}
