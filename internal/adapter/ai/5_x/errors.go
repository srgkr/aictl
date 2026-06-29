package client5x

import (
	"io"
	"net/http"

	"github.com/POSIdev-community/aictl/internal/core/apperror"
	clientai5x "github.com/POSIdev-community/aictl/pkg/clientai/5_x"
)

func CheckResponse(rsp *http.Response, resourceName string) error {
	if rsp == nil {
		return apperror.NewEmptyResponseError(resourceName)
	}

	if rsp.StatusCode < 400 {
		return nil
	}

	var bytes []byte
	var body string
	_, err := rsp.Body.Read(bytes)
	if err != nil {
		if err != io.EOF {
			body = ""
		}
	}

	return checkResponseCommon(rsp.StatusCode, body, nil, resourceName)
}

func CheckResponseByModel(statusCode int, body string, model *clientai5x.ApiErrorModel) error {
	if model != nil && model.ErrorCode != nil && model.Details != nil {
		var errorCode = string(*model.ErrorCode)

		return apperror.CheckApiErrorModel(statusCode, errorCode, *model.Details)
	}

	return checkResponseCommon(statusCode, body, nil, "")
}

func checkResponseCommon(statusCode int, body string, model *clientai5x.ApiErrorModel, resourceName string) error {
	if statusCode < 400 {
		return nil
	}

	if statusCode >= 500 {
		return apperror.NewServerError(statusCode, body)
	}

	if model != nil {
		var errorCode = string(*model.ErrorCode)

		return apperror.CheckApiErrorModel(statusCode, errorCode, *model.Details)
	}

	return apperror.CheckResponseErrors(statusCode, body, resourceName)
}
