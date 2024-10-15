/*
 * Adyen Payment API
 *
 * The version of the OpenAPI document: 68
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.payment;

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
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * ResponseAdditionalDataOpi
 */
@JsonPropertyOrder({
  ResponseAdditionalDataOpi.JSON_PROPERTY_OPI_TRANS_TOKEN
})

public class ResponseAdditionalDataOpi {
  public static final String JSON_PROPERTY_OPI_TRANS_TOKEN = "opi.transToken";
  private String opiTransToken;

  public ResponseAdditionalDataOpi() { 
  }

  /**
   * Returned in the response if you included &#x60;opi.includeTransToken: true&#x60; in an ecommerce payment request. This contains an Oracle Payment Interface token that you can store in your Oracle Opera database to identify tokenized ecommerce transactions. For more information and required settings, see [Oracle Opera](https://docs.adyen.com/plugins/oracle-opera#opi-token-ecommerce).
   *
   * @param opiTransToken
   * @return the current {@code ResponseAdditionalDataOpi} instance, allowing for method chaining
   */
  public ResponseAdditionalDataOpi opiTransToken(String opiTransToken) {
    this.opiTransToken = opiTransToken;
    return this;
  }

  /**
   * Returned in the response if you included &#x60;opi.includeTransToken: true&#x60; in an ecommerce payment request. This contains an Oracle Payment Interface token that you can store in your Oracle Opera database to identify tokenized ecommerce transactions. For more information and required settings, see [Oracle Opera](https://docs.adyen.com/plugins/oracle-opera#opi-token-ecommerce).
   * @return opiTransToken
   */
  @ApiModelProperty(value = "Returned in the response if you included `opi.includeTransToken: true` in an ecommerce payment request. This contains an Oracle Payment Interface token that you can store in your Oracle Opera database to identify tokenized ecommerce transactions. For more information and required settings, see [Oracle Opera](https://docs.adyen.com/plugins/oracle-opera#opi-token-ecommerce).")
  @JsonProperty(JSON_PROPERTY_OPI_TRANS_TOKEN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getOpiTransToken() {
    return opiTransToken;
  }

  /**
   * Returned in the response if you included &#x60;opi.includeTransToken: true&#x60; in an ecommerce payment request. This contains an Oracle Payment Interface token that you can store in your Oracle Opera database to identify tokenized ecommerce transactions. For more information and required settings, see [Oracle Opera](https://docs.adyen.com/plugins/oracle-opera#opi-token-ecommerce).
   *
   * @param opiTransToken
   */ 
  @JsonProperty(JSON_PROPERTY_OPI_TRANS_TOKEN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setOpiTransToken(String opiTransToken) {
    this.opiTransToken = opiTransToken;
  }

  /**
   * Return true if this ResponseAdditionalDataOpi object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ResponseAdditionalDataOpi responseAdditionalDataOpi = (ResponseAdditionalDataOpi) o;
    return Objects.equals(this.opiTransToken, responseAdditionalDataOpi.opiTransToken);
  }

  @Override
  public int hashCode() {
    return Objects.hash(opiTransToken);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ResponseAdditionalDataOpi {\n");
    sb.append("    opiTransToken: ").append(toIndentedString(opiTransToken)).append("\n");
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
   * Create an instance of ResponseAdditionalDataOpi given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of ResponseAdditionalDataOpi
   * @throws JsonProcessingException if the JSON string is invalid with respect to ResponseAdditionalDataOpi
   */
  public static ResponseAdditionalDataOpi fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, ResponseAdditionalDataOpi.class);
  }
/**
  * Convert an instance of ResponseAdditionalDataOpi to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
