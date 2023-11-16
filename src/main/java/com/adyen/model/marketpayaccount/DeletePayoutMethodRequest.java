/*
 * Account API
 * This API is used for the classic integration. If you are just starting your implementation, refer to our [new integration guide](https://docs.adyen.com/marketplaces-and-platforms) instead.  The Account API provides endpoints for managing account-related entities on your platform. These related entities include account holders, accounts, bank accounts, shareholders, and verification-related documents. The management operations include actions such as creation, retrieval, updating, and deletion of them.  For more information, refer to our [documentation](https://docs.adyen.com/marketplaces-and-platforms/classic). ## Authentication Your Adyen contact will provide your API credential and an API key. To connect to the API, add an `X-API-Key` header with the API key as the value, for example:   ``` curl -H \"Content-Type: application/json\" \\ -H \"X-API-Key: YOUR_API_KEY\" \\ ... ```  Alternatively, you can use the username and password to connect to the API using basic authentication. For example:  ``` curl -U \"ws@MarketPlace.YOUR_PLATFORM_ACCOUNT\":\"YOUR_WS_PASSWORD\" \\ -H \"Content-Type: application/json\" \\ ... ``` When going live, you need to generate new web service user credentials to access the [live endpoints](https://docs.adyen.com/development-resources/live-endpoints).  ## Versioning The Account API supports [versioning](https://docs.adyen.com/development-resources/versioning) using a version suffix in the endpoint URL. This suffix has the following format: \"vXX\", where XX is the version number.  For example: ``` https://cal-test.adyen.com/cal/services/Account/v6/createAccountHolder ```
 *
 * The version of the OpenAPI document: 6
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.marketpayaccount;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.ArrayList;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * DeletePayoutMethodRequest
 */
@JsonPropertyOrder({
  DeletePayoutMethodRequest.JSON_PROPERTY_ACCOUNT_HOLDER_CODE,
  DeletePayoutMethodRequest.JSON_PROPERTY_PAYOUT_METHOD_CODES
})

public class DeletePayoutMethodRequest {
  public static final String JSON_PROPERTY_ACCOUNT_HOLDER_CODE = "accountHolderCode";
  private String accountHolderCode;

  public static final String JSON_PROPERTY_PAYOUT_METHOD_CODES = "payoutMethodCodes";
  private List<String> payoutMethodCodes = new ArrayList<>();

  public DeletePayoutMethodRequest() { 
  }

  public DeletePayoutMethodRequest accountHolderCode(String accountHolderCode) {
    this.accountHolderCode = accountHolderCode;
    return this;
  }

   /**
   * The code of the account holder, from which to delete the payout methods.
   * @return accountHolderCode
  **/
  @ApiModelProperty(required = true, value = "The code of the account holder, from which to delete the payout methods.")
  @JsonProperty(JSON_PROPERTY_ACCOUNT_HOLDER_CODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getAccountHolderCode() {
    return accountHolderCode;
  }


  @JsonProperty(JSON_PROPERTY_ACCOUNT_HOLDER_CODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAccountHolderCode(String accountHolderCode) {
    this.accountHolderCode = accountHolderCode;
  }


  public DeletePayoutMethodRequest payoutMethodCodes(List<String> payoutMethodCodes) {
    this.payoutMethodCodes = payoutMethodCodes;
    return this;
  }

  public DeletePayoutMethodRequest addPayoutMethodCodesItem(String payoutMethodCodesItem) {
    this.payoutMethodCodes.add(payoutMethodCodesItem);
    return this;
  }

   /**
   * The codes of the payout methods to be deleted.
   * @return payoutMethodCodes
  **/
  @ApiModelProperty(required = true, value = "The codes of the payout methods to be deleted.")
  @JsonProperty(JSON_PROPERTY_PAYOUT_METHOD_CODES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<String> getPayoutMethodCodes() {
    return payoutMethodCodes;
  }


  @JsonProperty(JSON_PROPERTY_PAYOUT_METHOD_CODES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPayoutMethodCodes(List<String> payoutMethodCodes) {
    this.payoutMethodCodes = payoutMethodCodes;
  }


  /**
   * Return true if this DeletePayoutMethodRequest object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    DeletePayoutMethodRequest deletePayoutMethodRequest = (DeletePayoutMethodRequest) o;
    return Objects.equals(this.accountHolderCode, deletePayoutMethodRequest.accountHolderCode) &&
        Objects.equals(this.payoutMethodCodes, deletePayoutMethodRequest.payoutMethodCodes);
  }

  @Override
  public int hashCode() {
    return Objects.hash(accountHolderCode, payoutMethodCodes);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DeletePayoutMethodRequest {\n");
    sb.append("    accountHolderCode: ").append(toIndentedString(accountHolderCode)).append("\n");
    sb.append("    payoutMethodCodes: ").append(toIndentedString(payoutMethodCodes)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

/**
   * Create an instance of DeletePayoutMethodRequest given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of DeletePayoutMethodRequest
   * @throws JsonProcessingException if the JSON string is invalid with respect to DeletePayoutMethodRequest
   */
  public static DeletePayoutMethodRequest fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, DeletePayoutMethodRequest.class);
  }
/**
  * Convert an instance of DeletePayoutMethodRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
