package semver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConstraints_Overlaps(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		// Basic intervals
		{name: "overlapping ranges", a: ">= 1.1.0, < 2.0.0", b: "> 1.5.0", want: true},
		{name: "adjacent open boundaries", a: ">= 1.0.0, < 1.5.0", b: ">= 1.5.0, < 2.0.0", want: false},
		{name: "adjacent closed boundary", a: ">= 1.0.0, <= 1.5.0", b: ">= 1.5.0, < 2.0.0", want: true},
		{name: "disjoint ranges", a: ">= 1.0.0, < 1.5.0", b: ">= 2.0.0, < 3.0.0", want: false},
		{name: "contained ranges", a: ">= 1.0.0, < 4.0.0", b: ">= 2.0.0, < 3.0.0", want: true},
		{name: "point inside range", a: "2.1.0", b: ">= 2.0.0, < 3.0.0", want: true},
		{name: "point outside range", a: "4.1.0", b: ">= 2.0.0, < 3.0.0", want: false},
		{name: "same point", a: "2.1.0", b: "2.1.0", want: true},
		{name: "strict bounds exclude point", a: "2.0.0", b: "> 2.0.0, < 3.0.0", want: false},

		// Wildcards
		{name: "universe overlaps", a: "*", b: ">= 1.0.0", want: true},
		{name: "empty is universe", a: "", b: ">= 1.0.0", want: true},
		{name: "major wildcard overlap", a: "2.*", b: ">= 2.5.0, < 3.0.0", want: true},
		{name: "major wildcard disjoint", a: "2.*", b: ">= 3.0.0", want: false},
		{name: "minor wildcard overlap", a: "2.1.*", b: "= 2.1.9", want: true},
		{name: "minor wildcard disjoint", a: "2.1.*", b: "= 2.2.0", want: false},
		{name: "wildcard equality range", a: "4.1.x", b: "< 4.2.0", want: true},

		// Tilde and caret
		{name: "caret overlaps", a: "^1.2.3", b: ">= 1.9.0, < 2.0.0", want: true},
		{name: "caret disjoint next major", a: "^1.2.3", b: ">= 2.0.0", want: false},
		{name: "caret zero major", a: "^0.2.3", b: ">= 0.2.9, < 0.3.0", want: true},
		{name: "caret wildcard", a: "^1.x", b: "= 1.9.0", want: true},
		{name: "caret wildcard disjoint", a: "^1.x", b: "= 2.0.0", want: false},
		{name: "tilde overlaps", a: "~1.2.3", b: ">= 1.2.9", want: true},
		{name: "tilde disjoint", a: "~1.2.3", b: ">= 1.3.0", want: false},
		{name: "tilde major wildcard", a: "~1", b: "= 1.9.0", want: true},

		// Not equal, including wildcard exclusions
		{name: "not equal leaves range", a: "!= 2.0.0", b: ">= 1.0.0, < 3.0.0", want: true},
		{name: "not equal removes singleton", a: "!= 2.0.0", b: "2.0.0", want: false},
		{name: "not equal different singleton", a: "!= 2.0.0", b: "2.0.1", want: true},
		{name: "wildcard not equal removes range", a: "!= 4.1.x", b: "4.1", want: false},
		{name: "wildcard not equal keeps outside", a: "!= 4.1.x", b: "4.2.0", want: true},
		{name: "major wildcard not equal", a: "!= 4.x", b: "4.1.0", want: false},
		{name: "major wildcard not equal outside", a: "!= 4.x", b: "5.0.0", want: true},

		// OR / AND
		{name: "or disjoint one overlap", a: "< 1.0.0 || > 2.0.0", b: ">= 2.5.0", want: true},
		{name: "or disjoint no overlap", a: "< 1.0.0 || = 2.0.0", b: "> 2.0.0, < 2.5.0", want: false},
		{name: "and with exclusion still overlaps", a: ">= 1.1.0, < 2.0.0, != 1.2.3", b: "= 1.5.0", want: true},
		{name: "and with exclusion removes point", a: ">= 1.1.0, < 2.0.0, != 1.2.3", b: "= 1.2.3", want: false},

		// Pre-release
		{name: "prerelease excluded by default", a: ">= 1.0.0", b: ">= 1.0.0-alpha, < 1.0.0", want: false},
		{name: "prerelease comparator missing on one atom", a: ">= 1.0.0-alpha", b: "< 1.0.0", want: false},
		{name: "prerelease comparators on all atoms", a: ">= 1.0.0-alpha", b: "< 1.0.0-beta", want: true},
		{name: "prerelease point", a: "1.0.0-alpha.2", b: ">= 1.0.0-alpha.1, < 1.0.0-beta", want: true},
		{name: "prerelease point below lower bound", a: "1.0.0-alpha.0", b: ">= 1.0.0-alpha.1, < 1.0.0-beta", want: false},
		{name: "prerelease intervals intersect below stable", a: ">= 1.0.0-alpha, < 1.0.0-z", b: ">= 1.0.0-beta, < 1.0.0-z", want: true},
		{name: "numeric prerelease comparator", a: ">= 1.0.0-0", b: "= 1.0.0-1", want: true},
		{name: "prerelease tilde", a: "~1.2.3-beta.2", b: "= 1.2.3-beta.4", want: true},
		{name: "prerelease caret boundary", a: "^1.1.2-alpha", b: "= 2.0.0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewConstraints(tt.a)
			require.NoError(t, err)
			b, err := NewConstraints(tt.b)
			require.NoError(t, err)

			require.Equal(t, tt.want, a.Overlaps(b), "a.Overlaps(b)")
			require.Equal(t, tt.want, b.Overlaps(a), "b.Overlaps(a) must be symmetric")
		})
	}
}

func TestConstraints_OverlapsWithPreRelease(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "prerelease included by option", a: ">= 1.0.0-alpha", b: "< 1.0.0", want: true},
		{name: "universe with prerelease", a: "*", b: ">= 0.0.0-alpha", want: true},
		{name: "prerelease caret boundary", a: "^1.1.2-alpha", b: "= 2.0.0", want: false},
		{name: "prerelease below stable boundary", a: "^1.1.2-alpha", b: "2.*", want: true},
		{name: "prerelease range intersection", a: ">= 0.0.0-0", b: "< 0.0.0-z", want: true},
		{name: "prerelease range disjoint", a: ">= 1.0.0", b: "< 1.0.0-alpha", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewConstraints(tt.a, WithPreRelease(true))
			require.NoError(t, err)
			b, err := NewConstraints(tt.b, WithPreRelease(true))
			require.NoError(t, err)

			require.Equal(t, tt.want, a.Overlaps(b))
			require.Equal(t, tt.want, b.Overlaps(a))
		})
	}
}

func TestConstraints_OverlapsWithZeroPadding(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		// With zero padding, "2" means 2.0.0 exactly.
		{name: "padded point mismatch", a: "2", b: "2.0.1", want: false},
		{name: "padded point match", a: "2", b: "2.0.0", want: true},
		{name: "padded range", a: ">= 1", b: ">= 1.0.5", want: true},
		{name: "padded wildcard-less compare", a: "< 1", b: ">= 1.0.0", want: false},
		{name: "padded prerelease", a: "> 0", b: "= 0.0.1-alpha", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewConstraints(tt.a, WithZeroPadding(true), WithPreRelease(true))
			require.NoError(t, err)
			b, err := NewConstraints(tt.b, WithZeroPadding(true), WithPreRelease(true))
			require.NoError(t, err)

			require.Equal(t, tt.want, a.Overlaps(b))
			require.Equal(t, tt.want, b.Overlaps(a))
		})
	}
}

func TestConstraints_OverlapsMatchesCheck(t *testing.T) {
	pairs := [][2]string{
		{">= 1.1.0, < 2.0.0", "^1.x"},
		{"!=4.1.x", "4.1"},
		{"~1.2.3", ">= 1.2.5, < 1.3.0"},
		{"*", "0.0.x"},
		{">=1.1, <2, !=1.2.3 || > 3", "= 1.2.3"},
		{">=1.1, <2, !=1.2.3 || > 3", "= 1.9.0"},
		{">=1.1, <2, !=1.2.3 || > 3", "= 4.0.0"},
	}
	versions := []string{
		"0.0.0", "0.0.1", "1.0.0", "1.1.0", "1.2.3", "1.2.5", "1.5.0",
		"1.9.0", "2.0.0", "3.0.0", "4.0.0", "4.1.0", "5.0.0",
	}

	for _, pair := range pairs {
		a, err := NewConstraints(pair[0])
		require.NoError(t, err)
		b, err := NewConstraints(pair[1])
		require.NoError(t, err)

		want := false
		for _, raw := range versions {
			v, err := Parse(raw)
			require.NoError(t, err)
			if a.Check(v) && b.Check(v) {
				want = true
				break
			}
		}
		require.Equal(t, want, a.Overlaps(b), pair[0]+" vs "+pair[1])
		require.Equal(t, want, b.Overlaps(a), pair[1]+" vs "+pair[0])
	}
}
