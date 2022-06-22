// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// __          __              _
// \ \        / /             (_)
//  \ \  /\  / /_ _ _ __ _ __  _ _ __   __ _
//   \ \/  \/ / _` | '__| '_ \| | '_ \ / _` |
//    \  /\  / (_| | |  | | | | | | | | (_| | : This file is generated, do not edit it.
//     \/  \/ \__,_|_|  |_| |_|_|_| |_|\__, |
//                                      __/ |
//                                     |___/

package rest_model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// PostureCheckType posture check type
//
// swagger:model postureCheckType
type PostureCheckType string

func NewPostureCheckType(value PostureCheckType) *PostureCheckType {
	v := value
	return &v
}

const (

	// PostureCheckTypeOS captures enum value "OS"
	PostureCheckTypeOS PostureCheckType = "OS"

	// PostureCheckTypePROCESS captures enum value "PROCESS"
	PostureCheckTypePROCESS PostureCheckType = "PROCESS"

	// PostureCheckTypeDOMAIN captures enum value "DOMAIN"
	PostureCheckTypeDOMAIN PostureCheckType = "DOMAIN"

	// PostureCheckTypeMAC captures enum value "MAC"
	PostureCheckTypeMAC PostureCheckType = "MAC"

	// PostureCheckTypeMFA captures enum value "MFA"
	PostureCheckTypeMFA PostureCheckType = "MFA"

	// PostureCheckTypePROCESSMULTI captures enum value "PROCESS_MULTI"
	PostureCheckTypePROCESSMULTI PostureCheckType = "PROCESS_MULTI"
)

// for schema
var postureCheckTypeEnum []interface{}

func init() {
	var res []PostureCheckType
	if err := json.Unmarshal([]byte(`["OS","PROCESS","DOMAIN","MAC","MFA","PROCESS_MULTI"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		postureCheckTypeEnum = append(postureCheckTypeEnum, v)
	}
}

func (m PostureCheckType) validatePostureCheckTypeEnum(path, location string, value PostureCheckType) error {
	if err := validate.EnumCase(path, location, value, postureCheckTypeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this posture check type
func (m PostureCheckType) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validatePostureCheckTypeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this posture check type based on context it is used
func (m PostureCheckType) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
