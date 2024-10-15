/*
 * Management Webhooks
 *
 * The version of the OpenAPI document: 3
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.managementwebhooks;

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
 * AccountNotificationResponse
 */
@JsonPropertyOrder({
  AccountNotificationResponse.JSON_PROPERTY_NOTIFICATION_RESPONSE
})

public class AccountNotificationResponse {
  public static final String JSON_PROPERTY_NOTIFICATION_RESPONSE = "notificationResponse";
  private String notificationResponse;

  public AccountNotificationResponse() { 
  }

  /**
   * Respond with any **2xx** HTTP status code to [accept the webhook](https://docs.adyen.com/development-resources/webhooks#accept-notifications).
   *
   * @param notificationResponse
   * @return the current {@code AccountNotificationResponse} instance, allowing for method chaining
   */
  public AccountNotificationResponse notificationResponse(String notificationResponse) {
    this.notificationResponse = notificationResponse;
    return this;
  }

  /**
   * Respond with any **2xx** HTTP status code to [accept the webhook](https://docs.adyen.com/development-resources/webhooks#accept-notifications).
   * @return notificationResponse
   */
  @ApiModelProperty(value = "Respond with any **2xx** HTTP status code to [accept the webhook](https://docs.adyen.com/development-resources/webhooks#accept-notifications).")
  @JsonProperty(JSON_PROPERTY_NOTIFICATION_RESPONSE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getNotificationResponse() {
    return notificationResponse;
  }

  /**
   * Respond with any **2xx** HTTP status code to [accept the webhook](https://docs.adyen.com/development-resources/webhooks#accept-notifications).
   *
   * @param notificationResponse
   */ 
  @JsonProperty(JSON_PROPERTY_NOTIFICATION_RESPONSE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setNotificationResponse(String notificationResponse) {
    this.notificationResponse = notificationResponse;
  }

  /**
   * Return true if this AccountNotificationResponse object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AccountNotificationResponse accountNotificationResponse = (AccountNotificationResponse) o;
    return Objects.equals(this.notificationResponse, accountNotificationResponse.notificationResponse);
  }

  @Override
  public int hashCode() {
    return Objects.hash(notificationResponse);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AccountNotificationResponse {\n");
    sb.append("    notificationResponse: ").append(toIndentedString(notificationResponse)).append("\n");
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
   * Create an instance of AccountNotificationResponse given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of AccountNotificationResponse
   * @throws JsonProcessingException if the JSON string is invalid with respect to AccountNotificationResponse
   */
  public static AccountNotificationResponse fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, AccountNotificationResponse.class);
  }
/**
  * Convert an instance of AccountNotificationResponse to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
