package semver

import (
	"github.com/aquasecurity/go-version/pkg/part"
)

// triple is a concrete major.minor.patch point in the release version space.
type triple struct {
	major, minor, patch uint64
}

func (t triple) compare(other triple) int {
	switch {
	case t.major != other.major:
		if t.major < other.major {
			return -1
		}
		return 1
	case t.minor != other.minor:
		if t.minor < other.minor {
			return -1
		}
		return 1
	case t.patch != other.patch:
		if t.patch < other.patch {
			return -1
		}
		return 1
	default:
		return 0
	}
}

// halfOpenRange is a [lo, hi) range of release triples. A range with hiInf
// extends to positive infinity.
type halfOpenRange struct {
	lo, hi triple
	hiInf  bool
}

func universeRange() halfOpenRange {
	return halfOpenRange{hiInf: true}
}

func (r halfOpenRange) empty() bool {
	return !r.hiInf && r.hi.compare(r.lo) <= 0
}

func (r halfOpenRange) intersect(other halfOpenRange) halfOpenRange {
	out := halfOpenRange{lo: r.lo, hi: r.hi, hiInf: r.hiInf}
	if other.lo.compare(out.lo) > 0 {
		out.lo = other.lo
	}
	if !other.hiInf {
		if out.hiInf || other.hi.compare(out.hi) < 0 {
			out.hi = other.hi
			out.hiInf = false
		}
	}
	return out
}

// subtract removes a [lo, hi) range. The result may contain two ranges when
// the exclusion falls in the middle.
func (r halfOpenRange) subtract(ex halfOpenRange) []halfOpenRange {
	if ex.empty() {
		return []halfOpenRange{r}
	}
	if ex.hi.compare(r.lo) <= 0 {
		return []halfOpenRange{r}
	}
	if !r.hiInf && ex.lo.compare(r.hi) >= 0 {
		return []halfOpenRange{r}
	}

	coversLeft := ex.lo.compare(r.lo) <= 0
	coversRight := ex.hiInf || (!r.hiInf && ex.hi.compare(r.hi) >= 0)
	switch {
	case coversLeft && coversRight:
		return nil
	case coversLeft:
		return []halfOpenRange{{lo: ex.hi, hi: r.hi, hiInf: r.hiInf}}
	case coversRight:
		return []halfOpenRange{{lo: r.lo, hi: ex.lo}}
	default:
		return []halfOpenRange{
			{lo: r.lo, hi: ex.lo},
			{lo: ex.hi, hi: r.hi, hiInf: r.hiInf},
		}
	}
}

func triValue(p part.Part) uint64 {
	switch t := p.(type) {
	case part.Uint64:
		return uint64(t)
	case part.Empty:
		// Empty parts compare as zero regardless of their wildcard flag.
		return 0
	default:
		// Wildcards are normalized to zero by Min before conversion.
		return 0
	}
}

func triFromVersion(v Version) triple {
	min := v.Min()
	return triple{
		major: triValue(min.major),
		minor: triValue(min.minor),
		patch: triValue(min.patch),
	}
}

func maxUint64() uint64 {
	return ^uint64(0)
}

type groupShape struct {
	// infeasible is true when a wildcard constraint carries a concrete
	// pre-release, which preCheck rejects for every version.
	infeasible bool
	// preAllowed is true when pre-release versions can satisfy the group.
	preAllowed bool
	ranges     []halfOpenRange
	// concrete pre-release and boundary versions used to build probes.
	roots    []string
	preSeeds []Version
}

// releaseRange converts an atom into the range of release versions it
// accepts. The second return value is false for "!=" atoms, which are
// collected as exclusions instead.
func releaseRange(c constraint) (halfOpenRange, bool) {
	v := c.version
	concrete := !v.IsAny()
	lo := triFromVersion(v)

	switch c.operatorName {
	case "", "=", "==":
		if !concrete {
			hi, inf := wildcardUpper(v)
			return halfOpenRange{lo: lo, hi: hi, hiInf: inf}, true
		}
		// An equality constraint with a concrete pre-release cannot match any
		// release version.
		if !v.preRelease.IsNull() {
			return halfOpenRange{}, true
		}
		return halfOpenRange{lo: lo, hi: successor(lo)}, true
	case ">":
		if concrete {
			return halfOpenRange{lo: successor(lo), hiInf: true}, true
		}
		return halfOpenRange{lo: tildeBumpTriple(v), hiInf: true}, true
	case ">=", "=>":
		return halfOpenRange{lo: lo, hiInf: true}, true
	case "<":
		return halfOpenRange{hi: lo}, true
	case "<=", "=<":
		if concrete {
			return halfOpenRange{hi: successor(lo)}, true
		}
		hi, inf := wildcardUpper(v)
		return halfOpenRange{hi: hi, hiInf: inf}, true
	case "~":
		hi, inf := tildeBumpOrInf(v)
		return halfOpenRange{lo: lo, hi: hi, hiInf: inf}, true
	case "^":
		hi, inf := caretBumpOrInf(v)
		return halfOpenRange{lo: lo, hi: hi, hiInf: inf}, true
	case "!=":
		return halfOpenRange{}, false
	default:
		return universeRange(), true
	}
}

func successor(t triple) triple {
	if t.patch != maxUint64() {
		t.patch++
		return t
	}
	t.patch = 0
	if t.minor != maxUint64() {
		t.minor++
		return t
	}
	t.minor = 0
	t.major++
	return t
}

func tildeBumpTriple(v Version) triple {
	t, _ := tildeBumpOrInf(v)
	return t
}

func tildeBumpOrInf(v Version) (triple, bool) {
	bumped := v.TildeBump()
	if bumped.major == part.Uint64(maxUint64()) {
		return triple{}, true
	}
	return triFromVersion(bumped), false
}

func caretBumpOrInf(v Version) (triple, bool) {
	bumped := v.CaretBump()
	if bumped.major == part.Uint64(maxUint64()) {
		return triple{}, true
	}
	return triFromVersion(bumped), false
}

// exclusionRange converts a "!=" atom into the release range it rejects.
func exclusionRange(c constraint) halfOpenRange {
	v := c.version
	if v.IsAny() {
		hi, inf := wildcardUpper(v)
		return halfOpenRange{lo: triFromVersion(v), hi: hi, hiInf: inf}
	}
	lo := triFromVersion(v)
	return halfOpenRange{lo: lo, hi: successor(lo)}
}

// wildcardUpper returns the exclusive upper bound of a wildcard version:
// the segment immediately after the first wildcard (or missing segment) is
// incremented, matching how "=" handles wildcard versions.
func wildcardUpper(v Version) (triple, bool) {
	switch {
	case v.major.IsAny(), v.major.IsEmpty():
		return triple{}, true
	case v.minor.IsAny(), v.minor.IsEmpty():
		t := triFromVersion(v)
		t.minor = 0
		t.patch = 0
		t.major++
		return t, false
	case v.patch.IsAny(), v.patch.IsEmpty():
		t := triFromVersion(v)
		t.patch = 0
		t.minor++
		return t, false
	default:
		t := triFromVersion(v)
		return successor(t), false
	}
}

func buildGroupShape(atoms []constraint, conf conf) groupShape {
	shape := groupShape{
		// WithPreRelease allows pre-release versions unconditionally.
		// Otherwise they are allowed only when every atom carries a
		// concrete pre-release comparator, mirroring preCheck.
		preAllowed: conf.includePreRelease,
		ranges:     []halfOpenRange{universeRange()},
	}
	if !conf.includePreRelease {
		shape.preAllowed = true
	}

	for _, atom := range atoms {
		v := atom.version
		hasPre := !v.preRelease.IsNull() && !v.preRelease.IsAny()
		if v.IsAny() && hasPre {
			shape.infeasible = true
		}
		if !conf.includePreRelease && !hasPre {
			shape.preAllowed = false
		}

		collectShapeSeeds(&shape, v)

		if atom.operatorName == "!=" {
			exclusion := exclusionRange(atom)
			var remaining []halfOpenRange
			for _, r := range shape.ranges {
				remaining = append(remaining, r.subtract(exclusion)...)
			}
			shape.ranges = remaining
			continue
		}

		atomRange, _ := releaseRange(atom)
		for i := range shape.ranges {
			shape.ranges[i] = shape.ranges[i].intersect(atomRange)
		}
	}

	var live []halfOpenRange
	for _, r := range shape.ranges {
		if !r.empty() {
			live = append(live, r)
		}
	}
	shape.ranges = live
	return shape
}

func collectShapeSeeds(shape *groupShape, v Version) {
	t := triFromVersion(v)
	shape.roots = append(shape.roots, triRoot(t))
	if !v.preRelease.IsNull() && !v.preRelease.IsAny() {
		shape.preSeeds = append(shape.preSeeds, v)
	}
}

func triRoot(t triple) string {
	return formatTriple(t)
}

// Overlaps reports whether the sets of versions satisfying cs and other
// share at least one version. Both AND (",") and OR ("||") combinations are
// supported: two constraints overlap when any AND group of each side has a
// common version.
//
// Pre-release inclusion and zero padding follow the options of each
// Constraints instance.
func (cs Constraints) Overlaps(other Constraints) bool {
	for _, leftAtoms := range cs.constraints {
		left := buildGroupShape(leftAtoms, cs.conf)
		if left.infeasible {
			continue
		}
		for _, rightAtoms := range other.constraints {
			right := buildGroupShape(rightAtoms, other.conf)
			if right.infeasible {
				continue
			}
			if groupsOverlap(left, right, leftAtoms, rightAtoms, cs.conf, other.conf) {
				return true
			}
		}
	}
	return false
}

func groupsOverlap(left, right groupShape, leftAtoms, rightAtoms []constraint,
	leftConf, rightConf conf) bool {
	if releaseRangesOverlap(left.ranges, right.ranges) {
		return true
	}

	if !left.preAllowed || !right.preAllowed {
		return false
	}

	for _, candidate := range preReleaseCandidates(left, right) {
		if andCheck(candidate, leftAtoms, leftConf) &&
			andCheck(candidate, rightAtoms, rightConf) {
			return true
		}
	}
	return false
}

func releaseRangesOverlap(left, right []halfOpenRange) bool {
	for _, l := range left {
		for _, r := range right {
			if !l.intersect(r).empty() {
				return true
			}
		}
	}
	return false
}

func preReleaseCandidates(left, right groupShape) []Version {
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

	for _, shape := range []groupShape{left, right} {
		for _, seed := range shape.preSeeds {
			add(seed)
			if v, err := Parse(formatTriple(triFromVersion(seed)) + "-0"); err == nil {
				add(v)
			}
		}
		for _, root := range shape.roots {
			// String identifiers sort above numeric ones and below the
			// stable release, so they probe gaps just beneath each root.
			for _, suffix := range []string{"-0", "-a", "-alpha", "-z"} {
				if v, err := Parse(root + suffix); err == nil {
					add(v)
				}
			}
		}
		for _, r := range shape.ranges {
			if v, err := Parse(formatTriple(r.lo) + "-0"); err == nil {
				add(v)
			}
		}
	}
	return candidates
}

func formatTriple(t triple) string {
	return uintToString(t.major) + "." + uintToString(t.minor) + "." + uintToString(t.patch)
}

func uintToString(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
