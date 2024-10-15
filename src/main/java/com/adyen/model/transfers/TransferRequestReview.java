/*
 * Transfers API
 *
 * The version of the OpenAPI document: 4
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.transfers;

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
 * TransferRequestReview
 */
@JsonPropertyOrder({
  TransferRequestReview.JSON_PROPERTY_NUMBER_OF_APPROVALS_REQUIRED,
  TransferRequestReview.JSON_PROPERTY_SCA_ON_APPROVAL
})

public class TransferRequestReview {
  public static final String JSON_PROPERTY_NUMBER_OF_APPROVALS_REQUIRED = "numberOfApprovalsRequired";
  private Integer numberOfApprovalsRequired;

  public static final String JSON_PROPERTY_SCA_ON_APPROVAL = "scaOnApproval";
  private Boolean scaOnApproval;

  public TransferRequestReview() { 
  }

  /**
   * Specifies the number of [approvals](https://docs.adyen.com/api-explorer/transfers/latest/post/transfers/approve) required to process the transfer.
   *
   * @param numberOfApprovalsRequired
   * @return the current {@code TransferRequestReview} instance, allowing for method chaining
   */
  public TransferRequestReview numberOfApprovalsRequired(Integer numberOfApprovalsRequired) {
    this.numberOfApprovalsRequired = numberOfApprovalsRequired;
    return this;
  }

  /**
   * Specifies the number of [approvals](https://docs.adyen.com/api-explorer/transfers/latest/post/transfers/approve) required to process the transfer.
   * @return numberOfApprovalsRequired
   */
  @ApiModelProperty(value = "Specifies the number of [approvals](https://docs.adyen.com/api-explorer/transfers/latest/post/transfers/approve) required to process the transfer.")
  @JsonProperty(JSON_PROPERTY_NUMBER_OF_APPROVALS_REQUIRED)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Integer getNumberOfApprovalsRequired() {
    return numberOfApprovalsRequired;
  }

  /**
   * Specifies the number of [approvals](https://docs.adyen.com/api-explorer/transfers/latest/post/transfers/approve) required to process the transfer.
   *
   * @param numberOfApprovalsRequired
   */ 
  @JsonProperty(JSON_PROPERTY_NUMBER_OF_APPROVALS_REQUIRED)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setNumberOfApprovalsRequired(Integer numberOfApprovalsRequired) {
    this.numberOfApprovalsRequired = numberOfApprovalsRequired;
  }

  /**
   * Specifies whether you will initiate Strong Customer Authentication (SCA) in thePOST [/transfers/approve](https://docs.adyen.com/api-explorer/transfers/latest/post/transfers/approve) request.  Only applies to transfers made with an Adyen [business account](https://docs.adyen.com/platforms/business-accounts).
   *
   * @param scaOnApproval
   * @return the current {@code TransferRequestReview} instance, allowing for method chaining
   */
  public TransferRequestReview scaOnApproval(Boolean scaOnApproval) {
    this.scaOnApproval = scaOnApproval;
    return this;
  }

  /**
   * Specifies whether you will initiate Strong Customer Authentication (SCA) in thePOST [/transfers/approve](https://docs.adyen.com/api-explorer/transfers/latest/post/transfers/approve) request.  Only applies to transfers made with an Adyen [business account](https://docs.adyen.com/platforms/business-accounts).
   * @return scaOnApproval
   */
  @ApiModelProperty(value = "Specifies whether you will initiate Strong Customer Authentication (SCA) in thePOST [/transfers/approve](https://docs.adyen.com/api-explorer/transfers/latest/post/transfers/approve) request.  Only applies to transfers made with an Adyen [business account](https://docs.adyen.com/platforms/business-accounts).")
  @JsonProperty(JSON_PROPERTY_SCA_ON_APPROVAL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Boolean getScaOnApproval() {
    return scaOnApproval;
  }

  /**
   * Specifies whether you will initiate Strong Customer Authentication (SCA) in thePOST [/transfers/approve](https://docs.adyen.com/api-explorer/transfers/latest/post/transfers/approve) request.  Only applies to transfers made with an Adyen [business account](https://docs.adyen.com/platforms/business-accounts).
   *
   * @param scaOnApproval
   */ 
  @JsonProperty(JSON_PROPERTY_SCA_ON_APPROVAL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setScaOnApproval(Boolean scaOnApproval) {
    this.scaOnApproval = scaOnApproval;
  }

  /**
   * Return true if this TransferRequestReview object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    TransferRequestReview transferRequestReview = (TransferRequestReview) o;
    return Objects.equals(this.numberOfApprovalsRequired, transferRequestReview.numberOfApprovalsRequired) &&
        Objects.equals(this.scaOnApproval, transferRequestReview.scaOnApproval);
  }

  @Override
  public int hashCode() {
    return Objects.hash(numberOfApprovalsRequired, scaOnApproval);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class TransferRequestReview {\n");
    sb.append("    numberOfApprovalsRequired: ").append(toIndentedString(numberOfApprovalsRequired)).append("\n");
    sb.append("    scaOnApproval: ").append(toIndentedString(scaOnApproval)).append("\n");
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
   * Create an instance of TransferRequestReview given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of TransferRequestReview
   * @throws JsonProcessingException if the JSON string is invalid with respect to TransferRequestReview
   */
  public static TransferRequestReview fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, TransferRequestReview.class);
  }
/**
  * Convert an instance of TransferRequestReview to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
