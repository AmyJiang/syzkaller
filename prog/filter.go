package prog

func Blacklist(p *Prog) bool {
	// FIXME: not very efficient
	/*
		for _, c := range p.Calls {
			if c.Meta.Name == "open" || c.Meta.Name == "open$dir" {
				if c.Args[1].Val&0x4000 != 0 {
					return true // open with O_DIRECT flag
				}
			}
		}
	*/
	return false
}
