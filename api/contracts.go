package api

type ErrorResponse struct {
	Error string `json:"error"`
}

type RefreshRequest struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type LoginReponse struct {
	AccessHash  string `json:"access"`
	RefreshHash string `json:"refresh"`
}

type ValidateRequest struct {
	AccessToken string `json: access"`
}

type ValidateResponse struct {
	Status string `json:"status"`
	Id     string `json:"id"`
}
