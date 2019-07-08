package main

func CheckErr(err error) {
	if err != nil {
		panic(err)
	}
}

func CanUseResources(resource string, resources []string) bool {
	if resource == "" || resources == nil {
		return false
	}
	for e := range resources {
		s := resources[e]
		if s == resource || s == "*" {
			return true
		}
	}
	return false
}
