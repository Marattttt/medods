package api

type ErrorResponse struct {
	Error string `json:"error"`
}

type StringResponse struct {
	Message string `json:"message"`
}

type RefreshRequest struct {
	Token string `json:"token"`
}

type LoginReponse struct {
	AccessHash  string `json:"access"`
	RefreshHash string `json:"refresh"`
}

type TokenStatusResponse struct {
	Status string `json:"status"`
	Id     string `json:"id"`
}
