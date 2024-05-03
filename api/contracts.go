package api

type ErrorResponse struct {
	Error string `json:"error"`
}

type StringResponse struct {
	Message string `json:"message"`
}

type RefreshRequest struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type LoginReponse struct {
	AccessHash  string `json:"access"`
	RefreshHash string `json:"refresh"`
}

type TokenStatusResponse struct {
	Status string `json:"status"`
	Id     string `json:"id"`
}
