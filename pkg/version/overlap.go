package version

import (
	"strconv"
	"strings"
)

// intervalBound is a single boundary of a version interval.
// When set is false the boundary is infinite: negative infinity for a
// lower boundary and positive infinity for an upper boundary.
type intervalBound struct {
	version   Version
	set       bool
	inclusive bool
}

// interval is a half-open/closed range over the totally ordered version
// space. Exclusions introduced by "!=" constraints are tracked separately.
type interval struct {
	low  intervalBound
	high intervalBound
}

func universe() interval {
	return interval{
		low:  intervalBound{inclusive: true},
		high: intervalBound{inclusive: false},
	}
}

// constrainLow intersects the interval with a lower boundary.
func (i interval) constrainLow(b intervalBound) interval {
	if !b.set {
		return i
	}
	if !i.low.set {
		i.low = b
		return i
	}

	switch b.version.Compare(i.low.version) {
	case 1:
		i.low = b
	case 0:
		i.low.inclusive = i.low.inclusive && b.inclusive
	}
	return i
}

// constrainHigh intersects the interval with an upper boundary.
func (i interval) constrainHigh(b intervalBound) interval {
	if !b.set {
		return i
	}
	if !i.high.set {
		i.high = b
		return i
	}

	switch b.version.Compare(i.high.version) {
	case -1:
		i.high = b
	case 0:
		i.high.inclusive = i.high.inclusive && b.inclusive
	}
	return i
}

// feasible reports whether the interval contains any version equivalence
// class. Exclusions are not considered here.
func (i interval) feasible() bool {
	if !i.low.set || !i.high.set {
		return true
	}

	switch i.low.version.Compare(i.high.version) {
	case -1:
		return true
	case 1:
		return false
	default:
		return i.low.inclusive && i.high.inclusive
	}
}

// isSingleton reports whether the interval covers a single equivalence class.
func (i interval) isSingleton() bool {
	return i.low.set && i.high.set &&
		i.low.inclusive && i.high.inclusive &&
		i.low.version.Compare(i.high.version) == 0
}

// atomInterval converts a single constraint into an interval. Constraints
// using the "!=" operator are represented by an empty interval and must be
// collected as exclusions by the caller.
func atomInterval(c Constraint) (interval, bool) {
	i := universe()
	switch c.operator {
	case "", "=", "==":
		b := intervalBound{version: c.version, set: true, inclusive: true}
		i.low = b
		i.high = b
	case ">":
		i.low = intervalBound{version: c.version, set: true, inclusive: false}
	case ">=", "=>":
		i.low = intervalBound{version: c.version, set: true, inclusive: true}
	case "<":
		i.high = intervalBound{version: c.version, set: true, inclusive: false}
	case "<=", "=<":
		i.high = intervalBound{version: c.version, set: true, inclusive: true}
	case "~>":
		i = rangeInterval(c.version, c.version.PessimisticBump())
	case "~":
		i = rangeInterval(c.version, c.version.TildeBump())
	case "^":
		i = rangeInterval(c.version, c.version.CaretBump())
	case "!=":
		return i, false
	default:
		i = universe()
	}
	return i, true
}

func rangeInterval(low, high Version) interval {
	return interval{
		low:  intervalBound{version: low, set: true, inclusive: true},
		high: intervalBound{version: high, set: true, inclusive: false},
	}
}

type groupShape struct {
	interval   interval
	exclusions []Version
	bounds     []Version
}

func buildGroupShape(constraints []Constraint) groupShape {
	shape := groupShape{interval: universe()}
	for _, c := range constraints {
		if c.operator == "!=" {
			shape.exclusions = append(shape.exclusions, c.version)
			continue
		}
		if iv, ok := atomInterval(c); ok {
			shape.interval = shape.interval.
				constrainLow(iv.low).
				constrainHigh(iv.high)
			if iv.low.set {
				shape.bounds = append(shape.bounds, iv.low.version)
			}
			if iv.high.set {
				shape.bounds = append(shape.bounds, iv.high.version)
			}
		}
	}
	return shape
}

// Overlaps reports whether the sets of versions satisfying cs and other
// share at least one version. Both AND (",") and OR ("||") combinations are
// supported: two constraints overlap when any AND group of each side has a
// common version.
//
// Each Constraints keeps its own options, so build metadata ordering is
// honored whenever the corresponding side opts into it.
func (cs Constraints) Overlaps(other Constraints) bool {
	for _, leftConstraints := range cs.constraints {
		left := buildGroupShape(leftConstraints)
		for _, rightConstraints := range other.constraints {
			right := buildGroupShape(rightConstraints)
			if groupsOverlap(left, right, cs.conf, other.conf,
				leftConstraints, rightConstraints) {
				return true
			}
		}
	}
	return false
}

func groupsOverlap(left, right groupShape, leftConf, rightConf conf,
	leftConstraints, rightConstraints []Constraint) bool {
	merged := left.interval.
		constrainLow(right.interval.low).
		constrainHigh(right.interval.high)

	if !merged.feasible() {
		// Bounds can collapse onto one equivalence class only when at least
		// one side orders build metadata: without that ordering, every
		// representative of the class is equal and an open boundary rejects
		// all of them.
		if merged.low.set && merged.high.set &&
			merged.low.version.Compare(merged.high.version) == 0 &&
			(buildMetadataOrdered(leftConf) || buildMetadataOrdered(rightConf)) {
			return probeVersionGroups(left, right, leftConf, rightConf,
				leftConstraints, rightConstraints)
		}
		return false
	}

	// A non-degenerate interval contains infinitely many version equivalence
	// classes (versions may have arbitrarily many segments), so finitely many
	// "!=" exclusions cannot empty it.
	if !merged.isSingleton() {
		return true
	}

	// A degenerate interval still covers the pre-release versions below the
	// stable class (e.g. 2.0.0-alpha < 2.0.0), and build metadata ordering may
	// further distinguish variants of the same class. Concrete witnesses are
	// therefore the only precise way to decide.
	if classWideExcluded(merged.low.version, left.exclusions, leftConf) ||
		classWideExcluded(merged.low.version, right.exclusions, rightConf) {
		return false
	}
	return probeVersionGroups(left, right, leftConf, rightConf,
		leftConstraints, rightConstraints)
}

// classWideExcluded reports whether an exclusion removes every
// representative of an equivalence class. A side that ignores build
// metadata compares all variants of a class as equal.
func classWideExcluded(class Version, exclusions []Version, c conf) bool {
	if buildMetadataOrdered(c) {
		return false
	}
	for _, exclusion := range exclusions {
		if exclusion.Compare(class) == 0 {
			return true
		}
	}
	return false
}

func buildMetadataOrdered(c conf) bool {
	return c.buildMetadataOrder == BuildMetadataOrderNodeSemver
}

// probeVersionGroups evaluates concrete candidate versions against both
// constraint groups. It is only used around build metadata ordering
// refinements, where symbolic interval reasoning cannot distinguish
// individual build metadata variants.
func probeVersionGroups(left, right groupShape, leftConf, rightConf conf,
	leftConstraints, rightConstraints []Constraint) bool {
	for _, candidate := range overlapCandidates(left, right) {
		if andCheck(candidate, leftConstraints, leftConf) &&
			andCheck(candidate, rightConstraints, rightConf) {
			return true
		}
	}
	return false
}

func overlapCandidates(left, right groupShape) []Version {
	seen := map[string]struct{}{}
	var candidates []Version

	add := func(v Version) {
		key := v.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, v)
	}

	var roots []string
	collect := func(v Version) {
		add(v)
		roots = append(roots, strings.SplitN(v.String(), "+", 2)[0])
	}
	for _, shape := range []groupShape{left, right} {
		for _, b := range shape.bounds {
			collect(b)
		}
		for _, exclusion := range shape.exclusions {
			add(exclusion)
			roots = append(roots, strings.SplitN(exclusion.String(), "+", 2)[0])
		}
	}

	// Pre-release witnesses directly below each stable boundary, e.g.
	// 2.0.0-alpha < 2.0.0. They decide degenerate intervals such as
	// "= 2.0.0" against ranges whose upper bound is 2.0.0.
	for _, root := range append([]string{}, roots...) {
		if strings.Contains(root, "-") {
			continue
		}
		for _, suffix := range []string{"-alpha", "-alpha.0", "-0"} {
			if v, err := Parse(root + suffix); err == nil {
				add(v)
			}
		}
	}

	// Generate more distinct build metadata variants than there are
	// exclusions, guaranteeing at least one variant cannot be excluded.
	exclusionCount := len(left.exclusions) + len(right.exclusions)
	for _, root := range roots {
		for i := 0; i < exclusionCount+2; i++ {
			if v, err := Parse(root + "+" + strconv.Itoa(i)); err == nil {
				add(v)
			}
		}
	}
	return candidates
}
