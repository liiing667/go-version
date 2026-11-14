package version

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
		{name: "overlapping ranges", a: ">= 1.0, < 2.0", b: "> 1.5", want: true},
		{name: "adjacent open boundaries", a: ">= 1.0, < 1.5", b: ">= 1.5, < 2.0", want: false},
		{name: "adjacent closed boundary", a: ">= 1.0, <= 1.5", b: ">= 1.5, < 2.0", want: true},
		{name: "disjoint ranges", a: ">= 1.0, < 1.5", b: ">= 2.0, < 3.0", want: false},
		{name: "contained ranges", a: ">= 1.0, < 4.0", b: ">= 2.0, < 3.0", want: true},
		{name: "point inside range", a: "2.1.0", b: ">= 2.0, < 3.0", want: true},
		{name: "point outside range", a: "4.1.0", b: ">= 2.0, < 3.0", want: false},
		{name: "same point", a: "2.1.0", b: "2.1.0", want: true},
		{name: "strict bounds exclude point", a: "2.0.0", b: "> 2.0.0, < 3.0.0", want: false},
		{name: "inclusive bounds include point", a: "2.0.0", b: ">= 2.0.0, <= 3.0.0", want: true},

		// OR combinations
		{name: "or disjoint one overlap", a: "< 1.0 || > 2.0", b: ">= 2.5", want: true},
		{name: "or disjoint no overlap", a: "< 1.0 || = 2.0", b: "> 2.0, < 2.5", want: false},
		{name: "or both sides", a: "< 1.0 || > 3.0", b: ">= 0.5, <= 0.8 || >= 4.0", want: true},

		// Tilde, caret, pessimistic
		{name: "caret overlaps", a: "^1.2.3", b: ">= 1.5.0, < 2.0.0", want: true},
		{name: "caret disjoint next major", a: "^1.2.3", b: ">= 2.0.0", want: false},
		{name: "caret boundary prerelease", a: "^1", b: "= 2.0.0", want: false},
		{name: "caret boundary prerelease overlap", a: "^1", b: ">= 2.0.0-alpha, < 2.0.0", want: true},
		{name: "tilde overlaps", a: "~1.2.3", b: ">= 1.2.5", want: true},
		{name: "tilde disjoint", a: "~1.2.3", b: ">= 1.3.0", want: false},
		{name: "pessimistic overlaps", a: "~> 1.0.7", b: ">= 1.0.9", want: true},
		{name: "pessimistic disjoint", a: "~> 1.0.7", b: ">= 1.1.0", want: false},

		// Not equal
		{name: "not equal leaves range", a: "!= 2.0.0", b: ">= 1.0, < 3.0", want: true},
		{name: "not equal removes singleton", a: "!= 2.0.0", b: "2.0.0", want: false},
		{name: "not equal different singleton", a: "!= 2.0.0", b: "2.0.1", want: true},

		// Pre-release
		{name: "prerelease range overlap", a: ">= 1.0.0-alpha", b: "< 1.0.0", want: true},
		{name: "prerelease point overlap", a: "1.0.0-alpha.1", b: ">= 1.0.0-alpha, < 1.0.0", want: true},
		{name: "prerelease disjoint", a: ">= 1.0.0", b: "< 1.0.0-alpha", want: false},
		{name: "prerelease bump boundary", a: "~1.2.3-beta.2", b: ">= 1.2.3-beta.4, < 1.3.0", want: true},
		{name: "prerelease only interval below stable", a: ">= 3.0.0-alpha", b: "< 3.0.0", want: true},
		{name: "prerelease sub interval", a: ">= 3.0.0-alpha", b: "< 3.0.0-alpha.5", want: true},
		{name: "prerelease disjoint order", a: ">= 3.0.0-beta", b: "< 3.0.0-alpha", want: false},

		// Zero padding (more than 3 segments)
		{name: "four segments overlap", a: ">= 1.0.0.0, < 1.0.0.5", b: "= 1.0.0.3", want: true},
		{name: "four segments disjoint", a: ">= 1.0.0.0, < 1.0.0.5", b: "= 1.0.0.5", want: false},
		{name: "padded equality", a: "1.0", b: "1.0.0", want: true},

		// Empty-result constraints
		{name: "impossible interval", a: ">= 2.0.0, < 2.0.0", b: ">= 1.0.0", want: false},
		{name: "empty vs universe-like", a: "> 2.0.0, < 2.0.0", b: "< 5.0.0", want: false},
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

func TestConstraints_OverlapsBuildMetadataNodeSemver(t *testing.T) {
	node := WithBuildMetadataOrder(BuildMetadataOrderNodeSemver)

	tests := []struct {
		name         string
		a            string
		b            string
		nodeA, nodeB bool
		want         bool
	}{
		{
			name:  "open boundary allows later build variant",
			a:     ">= 1.2.3+echo.1, < 1.2.3+echo.3",
			b:     "= 1.2.3+echo.2",
			nodeA: true, nodeB: true, want: true,
		},
		{
			name:  "open boundary excludes lower build variant",
			a:     ">= 1.2.3+echo.2",
			b:     "= 1.2.3+echo.1",
			nodeA: true, nodeB: true, want: false,
		},
		{
			name:  "closed singleton matches",
			a:     "= 1.2.3+echo.1",
			b:     ">= 1.2.3+echo.1, <= 1.2.3+echo.1",
			nodeA: true, nodeB: true, want: true,
		},
		{
			name:  "node not equal keeps another variant (default side)",
			a:     "!= 4.1",
			b:     "4.1",
			nodeA: true, nodeB: false, want: true,
		},
		{
			name:  "default not equal removes class",
			a:     "!= 4.1",
			b:     "4.1",
			nodeA: false, nodeB: true, want: false,
		},
		{
			name:  "default ignores build so open same class is empty",
			a:     ">= 1.2.3+echo.2",
			b:     "< 1.2.3+echo.2",
			nodeA: false, nodeB: false, want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var optsA, optsB []ConstraintOption
			if tt.nodeA {
				optsA = append(optsA, node)
			}
			if tt.nodeB {
				optsB = append(optsB, node)
			}
			a, err := NewConstraints(tt.a, optsA...)
			require.NoError(t, err)
			b, err := NewConstraints(tt.b, optsB...)
			require.NoError(t, err)

			require.Equal(t, tt.want, a.Overlaps(b))
		})
	}
}

func TestConstraints_OverlapsIsSymmetricWithCheck(t *testing.T) {
	// Every overlap witness discovered by Check on a finite version list must
	// agree with Overlaps for a representative set of constraint pairs.
	pairs := [][2]string{
		{">= 1.0, < 2.0", "^1.5"},
		{"~> 2.1.0-a", ">= 2.1.0, < 2.2.0"},
		{"< 1.0 || = 2.0", "^1"},
		{">= 1.0.0, < 1.2.0+security-01", "~1.1"},
		{"!= 1.2.3, >= 1.0, < 2.0", "= 1.2.3"},
		{"!= 1.2.3, >= 1.0, < 2.0", "= 1.2.4"},
	}
	versions := []string{
		"0.9.0", "1.0.0", "1.0.0-alpha", "1.1.0", "1.2.3", "1.2.4",
		"1.5.0", "1.9.9", "2.0.0-alpha", "2.0.0", "2.1.0-beta", "2.1.0",
		"2.1.5", "2.2.0", "3.0.0",
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
