package auth

type User struct {
	Id       string `json:"-"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Surname  string `json:"surname" binding:"required"`
	Address  string `json:"address" binding:"required"`
	RoleId   string `json:"-"`
}
