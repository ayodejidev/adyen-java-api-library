/*
 * Disputes API
 *
 * The version of the OpenAPI document: 30
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.disputes;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.adyen.model.disputes.DisputeServiceResult;
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
 * SupplyDefenseDocumentResponse
 */
@JsonPropertyOrder({
  SupplyDefenseDocumentResponse.JSON_PROPERTY_DISPUTE_SERVICE_RESULT
})

public class SupplyDefenseDocumentResponse {
  public static final String JSON_PROPERTY_DISPUTE_SERVICE_RESULT = "disputeServiceResult";
  private DisputeServiceResult disputeServiceResult;

  public SupplyDefenseDocumentResponse() { 
  }

  /**
   * disputeServiceResult
   *
   * @param disputeServiceResult
   * @return the current {@code SupplyDefenseDocumentResponse} instance, allowing for method chaining
   */
  public SupplyDefenseDocumentResponse disputeServiceResult(DisputeServiceResult disputeServiceResult) {
    this.disputeServiceResult = disputeServiceResult;
    return this;
  }

  /**
   * disputeServiceResult
   * @return disputeServiceResult
   */
  @ApiModelProperty(required = true, value = "")
  @JsonProperty(JSON_PROPERTY_DISPUTE_SERVICE_RESULT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public DisputeServiceResult getDisputeServiceResult() {
    return disputeServiceResult;
  }

  /**
   * disputeServiceResult
   *
   * @param disputeServiceResult
   */ 
  @JsonProperty(JSON_PROPERTY_DISPUTE_SERVICE_RESULT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDisputeServiceResult(DisputeServiceResult disputeServiceResult) {
    this.disputeServiceResult = disputeServiceResult;
  }

  /**
   * Return true if this SupplyDefenseDocumentResponse object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    SupplyDefenseDocumentResponse supplyDefenseDocumentResponse = (SupplyDefenseDocumentResponse) o;
    return Objects.equals(this.disputeServiceResult, supplyDefenseDocumentResponse.disputeServiceResult);
  }

  @Override
  public int hashCode() {
    return Objects.hash(disputeServiceResult);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class SupplyDefenseDocumentResponse {\n");
    sb.append("    disputeServiceResult: ").append(toIndentedString(disputeServiceResult)).append("\n");
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
   * Create an instance of SupplyDefenseDocumentResponse given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of SupplyDefenseDocumentResponse
   * @throws JsonProcessingException if the JSON string is invalid with respect to SupplyDefenseDocumentResponse
   */
  public static SupplyDefenseDocumentResponse fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, SupplyDefenseDocumentResponse.class);
  }
/**
  * Convert an instance of SupplyDefenseDocumentResponse to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
