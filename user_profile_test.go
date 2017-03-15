package otr4

import . "gopkg.in/check.v1"

func (s *OTR4Suite) Test_NewUserProfile(c *C) {
	exp := &userProfile{
		versions: []byte{4},
	}

	profile, err := newProfile([]byte{4})

	c.Assert(profile, DeepEquals, exp)
	c.Assert(err, IsNil)

	profile, err = newProfile([]byte{})

	c.Assert(profile, IsNil)
	c.Assert(err, ErrorMatches, ".* no valid version agreement could be found")

	profile, err = newProfile([]byte{0x01})

	c.Assert(profile, IsNil)
	c.Assert(err, ErrorMatches, ".* no valid version agreement could be found")

	profile, err = newProfile([]byte{0x03, 0x01})

	c.Assert(profile, IsNil)
	c.Assert(err, ErrorMatches, ".* no valid version agreement could be found")

	profile, err = newProfile([]byte{0x03, 0x02})

	c.Assert(profile, IsNil)
	c.Assert(err, ErrorMatches, ".* no valid version agreement could be found")
}
