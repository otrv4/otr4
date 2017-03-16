package otr4

import . "gopkg.in/check.v1"

func (s *OTR4Suite) Test_NewUserProfile(c *C) {
	exp := &userProfile{
		versions: "4",
	}

	profile, err := newProfile("4")

	c.Assert(profile, DeepEquals, exp)
	c.Assert(err, IsNil)

	profile, err = newProfile("")

	c.Assert(profile, IsNil)
	c.Assert(err, ErrorMatches, ".* no valid version agreement could be found")

	profile, err = newProfile("1")

	c.Assert(profile, IsNil)
	c.Assert(err, ErrorMatches, ".* no valid version agreement could be found")

	profile, err = newProfile("31")

	c.Assert(profile, IsNil)
	c.Assert(err, ErrorMatches, ".* no valid version agreement could be found")

	profile, err = newProfile("24")

	c.Assert(profile, IsNil)
	c.Assert(err, ErrorMatches, ".* no valid version agreement could be found")
}
