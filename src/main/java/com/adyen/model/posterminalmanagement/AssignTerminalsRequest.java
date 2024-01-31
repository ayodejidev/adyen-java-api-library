/*
 * POS Terminal Management API
 *
 * The version of the OpenAPI document: 1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.posterminalmanagement;

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
 * AssignTerminalsRequest
 */
@JsonPropertyOrder({
  AssignTerminalsRequest.JSON_PROPERTY_COMPANY_ACCOUNT,
  AssignTerminalsRequest.JSON_PROPERTY_MERCHANT_ACCOUNT,
  AssignTerminalsRequest.JSON_PROPERTY_MERCHANT_INVENTORY,
  AssignTerminalsRequest.JSON_PROPERTY_STORE,
  AssignTerminalsRequest.JSON_PROPERTY_TERMINALS
})

public class AssignTerminalsRequest {
  public static final String JSON_PROPERTY_COMPANY_ACCOUNT = "companyAccount";
  private String companyAccount;

  public static final String JSON_PROPERTY_MERCHANT_ACCOUNT = "merchantAccount";
  private String merchantAccount;

  public static final String JSON_PROPERTY_MERCHANT_INVENTORY = "merchantInventory";
  private Boolean merchantInventory;

  public static final String JSON_PROPERTY_STORE = "store";
  private String store;

  public static final String JSON_PROPERTY_TERMINALS = "terminals";
  private List<String> terminals = new ArrayList<>();

  public AssignTerminalsRequest() { 
  }

  public AssignTerminalsRequest companyAccount(String companyAccount) {
    this.companyAccount = companyAccount;
    return this;
  }

   /**
   * Your company account. To return terminals to the company inventory, specify only this parameter and the &#x60;terminals&#x60;.
   * @return companyAccount
  **/
  @ApiModelProperty(required = true, value = "Your company account. To return terminals to the company inventory, specify only this parameter and the `terminals`.")
  @JsonProperty(JSON_PROPERTY_COMPANY_ACCOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getCompanyAccount() {
    return companyAccount;
  }


 /**
  * Your company account. To return terminals to the company inventory, specify only this parameter and the &#x60;terminals&#x60;.
  *
  * @param companyAccount
  */ 
  @JsonProperty(JSON_PROPERTY_COMPANY_ACCOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCompanyAccount(String companyAccount) {
    this.companyAccount = companyAccount;
  }


  public AssignTerminalsRequest merchantAccount(String merchantAccount) {
    this.merchantAccount = merchantAccount;
    return this;
  }

   /**
   * Name of the merchant account. Specify this parameter to assign terminals to this merchant account or to a store under this merchant account.
   * @return merchantAccount
  **/
  @ApiModelProperty(value = "Name of the merchant account. Specify this parameter to assign terminals to this merchant account or to a store under this merchant account.")
  @JsonProperty(JSON_PROPERTY_MERCHANT_ACCOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getMerchantAccount() {
    return merchantAccount;
  }


 /**
  * Name of the merchant account. Specify this parameter to assign terminals to this merchant account or to a store under this merchant account.
  *
  * @param merchantAccount
  */ 
  @JsonProperty(JSON_PROPERTY_MERCHANT_ACCOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMerchantAccount(String merchantAccount) {
    this.merchantAccount = merchantAccount;
  }


  public AssignTerminalsRequest merchantInventory(Boolean merchantInventory) {
    this.merchantInventory = merchantInventory;
    return this;
  }

   /**
   * Boolean that indicates if you are assigning the terminals to the merchant inventory. Do not use when assigning terminals to a store. Required when assigning the terminal to a merchant account.  - Set this to **true** to assign the terminals to the merchant inventory. This also means that the terminals cannot be boarded.  - Set this to **false** to assign the terminals to the merchant account as in-store terminals. This makes the terminals ready to be boarded and to process payments through the specified merchant account.
   * @return merchantInventory
  **/
  @ApiModelProperty(value = "Boolean that indicates if you are assigning the terminals to the merchant inventory. Do not use when assigning terminals to a store. Required when assigning the terminal to a merchant account.  - Set this to **true** to assign the terminals to the merchant inventory. This also means that the terminals cannot be boarded.  - Set this to **false** to assign the terminals to the merchant account as in-store terminals. This makes the terminals ready to be boarded and to process payments through the specified merchant account.")
  @JsonProperty(JSON_PROPERTY_MERCHANT_INVENTORY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getMerchantInventory() {
    return merchantInventory;
  }


 /**
  * Boolean that indicates if you are assigning the terminals to the merchant inventory. Do not use when assigning terminals to a store. Required when assigning the terminal to a merchant account.  - Set this to **true** to assign the terminals to the merchant inventory. This also means that the terminals cannot be boarded.  - Set this to **false** to assign the terminals to the merchant account as in-store terminals. This makes the terminals ready to be boarded and to process payments through the specified merchant account.
  *
  * @param merchantInventory
  */ 
  @JsonProperty(JSON_PROPERTY_MERCHANT_INVENTORY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMerchantInventory(Boolean merchantInventory) {
    this.merchantInventory = merchantInventory;
  }


  public AssignTerminalsRequest store(String store) {
    this.store = store;
    return this;
  }

   /**
   * The store code of the store that you want to assign the terminals to.
   * @return store
  **/
  @ApiModelProperty(value = "The store code of the store that you want to assign the terminals to.")
  @JsonProperty(JSON_PROPERTY_STORE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getStore() {
    return store;
  }


 /**
  * The store code of the store that you want to assign the terminals to.
  *
  * @param store
  */ 
  @JsonProperty(JSON_PROPERTY_STORE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setStore(String store) {
    this.store = store;
  }


  public AssignTerminalsRequest terminals(List<String> terminals) {
    this.terminals = terminals;
    return this;
  }

  public AssignTerminalsRequest addTerminalsItem(String terminalsItem) {
    this.terminals.add(terminalsItem);
    return this;
  }

   /**
   * Array containing a list of terminal IDs that you want to assign or reassign to the merchant account or store, or that you want to return to the company inventory.  For example, &#x60;[\&quot;V400m-324689776\&quot;,\&quot;P400Plus-329127412\&quot;]&#x60;.
   * @return terminals
  **/
  @ApiModelProperty(required = true, value = "Array containing a list of terminal IDs that you want to assign or reassign to the merchant account or store, or that you want to return to the company inventory.  For example, `[\"V400m-324689776\",\"P400Plus-329127412\"]`.")
  @JsonProperty(JSON_PROPERTY_TERMINALS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<String> getTerminals() {
    return terminals;
  }


 /**
  * Array containing a list of terminal IDs that you want to assign or reassign to the merchant account or store, or that you want to return to the company inventory.  For example, &#x60;[\&quot;V400m-324689776\&quot;,\&quot;P400Plus-329127412\&quot;]&#x60;.
  *
  * @param terminals
  */ 
  @JsonProperty(JSON_PROPERTY_TERMINALS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setTerminals(List<String> terminals) {
    this.terminals = terminals;
  }


  /**
   * Return true if this AssignTerminalsRequest object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AssignTerminalsRequest assignTerminalsRequest = (AssignTerminalsRequest) o;
    return Objects.equals(this.companyAccount, assignTerminalsRequest.companyAccount) &&
        Objects.equals(this.merchantAccount, assignTerminalsRequest.merchantAccount) &&
        Objects.equals(this.merchantInventory, assignTerminalsRequest.merchantInventory) &&
        Objects.equals(this.store, assignTerminalsRequest.store) &&
        Objects.equals(this.terminals, assignTerminalsRequest.terminals);
  }

  @Override
  public int hashCode() {
    return Objects.hash(companyAccount, merchantAccount, merchantInventory, store, terminals);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AssignTerminalsRequest {\n");
    sb.append("    companyAccount: ").append(toIndentedString(companyAccount)).append("\n");
    sb.append("    merchantAccount: ").append(toIndentedString(merchantAccount)).append("\n");
    sb.append("    merchantInventory: ").append(toIndentedString(merchantInventory)).append("\n");
    sb.append("    store: ").append(toIndentedString(store)).append("\n");
    sb.append("    terminals: ").append(toIndentedString(terminals)).append("\n");
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
   * Create an instance of AssignTerminalsRequest given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of AssignTerminalsRequest
   * @throws JsonProcessingException if the JSON string is invalid with respect to AssignTerminalsRequest
   */
  public static AssignTerminalsRequest fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, AssignTerminalsRequest.class);
  }
/**
  * Convert an instance of AssignTerminalsRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

