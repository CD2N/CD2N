package chain

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/centrifuge/go-substrate-rpc-client/v4/registry"
	"github.com/centrifuge/go-substrate-rpc-client/v4/registry/parser"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

func DecodeEvent(event *parser.Event, value any) (err error) {
	defer func() {
		d := recover()
		if d != nil {
			err = fmt.Errorf("%v", d)
		}
	}()

	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.Wrap(errors.New("no pointer or nill value"), "decode event error")
	}
	rv = rv.Elem()
	rt := rv.Type()
	if rt.Kind() != reflect.Struct {
		return errors.Wrap(errors.New("no struct"), "decode event error")
	}
	if rt.Field(0).Type == reflect.TypeOf(types.Phase{}) {
		rv.Field(0).Set(reflect.ValueOf(*event.Phase))
	}
	return errors.Wrap(DecodeFields(rv, reflect.ValueOf(event.Fields)), "decode event error")
}

func DecodeFields(target, fv reflect.Value) error {
	tt, ft := target.Type(), fv.Type()
	if ft.Kind() == reflect.Interface {
		fv = fv.Elem()
	}

	if !fv.IsValid() || !target.CanSet() {
		return nil
	}

	switch tt.Kind() {
	case reflect.Struct:
		source := fv.Interface()
		fields, ok := source.(registry.DecodedFields)
		if !ok {
			if fv.CanConvert(reflect.TypeOf(uint8(0))) {
				index := source.(uint8)
				tfv := target.Field(int(index))
				tfv.SetBool(true)
				return nil
			}
			for i := 0; i < target.NumField() && i < fv.NumField(); i++ {
				if err := DecodeFields(target.Field(i), fv.Field(i)); err != nil {
					return err
				}
			}
		} else {
			offset := 0
			if tt.Field(0).Type == reflect.TypeOf(types.Phase{}) {
				offset = 1
			}
			for i, field := range fields {
				fieldName := ConvertName(field.Name)
				tfv := target.FieldByName(fieldName)

				if !tfv.IsValid() && tt.NumField() > i+offset {
					tfv = target.Field(i + offset)
				}
				if subfs, ok := field.Value.(registry.DecodedFields); ok {
					if len(subfs) == 1 && tfv.Kind() != reflect.Struct {
						field = subfs[0] //Unpacking Data
					}
				}
				if err := DecodeFields(tfv, reflect.ValueOf(field.Value)); err != nil {
					return err
				}
			}
		}
	case reflect.Array, reflect.Slice:
		var tmp reflect.Value
		et := tt.Elem()
		if fv.Kind() == reflect.Array {
			tmp = reflect.New(reflect.ArrayOf(fv.Len(), et)).Elem()
		} else {
			tmp = reflect.MakeSlice(reflect.SliceOf(et), fv.Len(), fv.Len())
		}

		tet := tmp.Type()

		if !tet.ConvertibleTo(tt) {
			return fmt.Errorf("type %v and %v mismatch", tet, tt)
		}
		for i := 0; i < fv.Len(); i++ {
			err := DecodeFields(tmp.Index(i), fv.Index(i).Elem())
			if err != nil {
				return err
			}
		}
		target.Set(tmp.Convert(tt))
	case reflect.Map:
		if fv.Kind() != reflect.Map {
			return fmt.Errorf("type %v and %v mismatch", ft, tt)
		}
		ttk, tte := tt.Key(), tt.Elem()
		tmp := reflect.MakeMap(reflect.MapOf(ttk, tte))
		iter := fv.MapRange()
		for iter.Next() {
			key := iter.Key()
			val := iter.Value()

			tk := reflect.New(ttk).Elem()
			tv := reflect.New(tte).Elem()
			if err := DecodeFields(tk, key); err != nil {
				return err
			}
			if err := DecodeFields(tv, val); err != nil {
				return err
			}
			tmp.SetMapIndex(tk, tv)
		}
		target.Set(tmp)
	default:
		if ft != tt {
			if !ft.ConvertibleTo(tt) {
				return fmt.Errorf("type %v and %v mismatch", ft, tt)
			}
			target.Set(fv.Convert(tt))
		} else {
			target.Set(fv)
		}

	}
	return nil
}

func ConvertName(name string) string {
	var res string
	bases := strings.Split(name, ".")
	words := strings.Split(bases[len(bases)-1], "_")
	for _, word := range words {
		if word != "" {
			res += strings.ToUpper(string(word[0])) + word[1:]
		}
	}
	return res
}
