package libsagernetcore

import (
	"github.com/dyhkwong/libsagernetcore/errors"
)

type errPathObjHolder struct{}

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...).WithPathObj(errPathObjHolder{})
}
