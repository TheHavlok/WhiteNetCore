package noderpc

import "database/sql"

// nullFloat and nullInt turn a zero from the wire into a NULL in the database.
//
// Zero and "not reported" are different things for a metric: a node whose
// agent could not read /proc must leave a gap in the chart rather than draw a
// line at zero.
func nullFloat(v float64) sql.NullFloat64 {
	if v == 0 {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: v, Valid: true}
}

func nullInt(v int64) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: v, Valid: true}
}
