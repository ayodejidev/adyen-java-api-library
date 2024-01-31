/*
 * Configuration API
 *
 * The version of the OpenAPI document: 2
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.balanceplatform;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.adyen.model.balanceplatform.AccountHolderCapability;
import com.adyen.model.balanceplatform.ContactDetails;
import com.adyen.model.balanceplatform.VerificationDeadline;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * AccountHolder
 */
@JsonPropertyOrder({
  AccountHolder.JSON_PROPERTY_BALANCE_PLATFORM,
  AccountHolder.JSON_PROPERTY_CAPABILITIES,
  AccountHolder.JSON_PROPERTY_CONTACT_DETAILS,
  AccountHolder.JSON_PROPERTY_DESCRIPTION,
  AccountHolder.JSON_PROPERTY_ID,
  AccountHolder.JSON_PROPERTY_LEGAL_ENTITY_ID,
  AccountHolder.JSON_PROPERTY_METADATA,
  AccountHolder.JSON_PROPERTY_MIGRATED_ACCOUNT_HOLDER_CODE,
  AccountHolder.JSON_PROPERTY_PRIMARY_BALANCE_ACCOUNT,
  AccountHolder.JSON_PROPERTY_REFERENCE,
  AccountHolder.JSON_PROPERTY_STATUS,
  AccountHolder.JSON_PROPERTY_TIME_ZONE,
  AccountHolder.JSON_PROPERTY_VERIFICATION_DEADLINES
})

public class AccountHolder {
  public static final String JSON_PROPERTY_BALANCE_PLATFORM = "balancePlatform";
  private String balancePlatform;

  public static final String JSON_PROPERTY_CAPABILITIES = "capabilities";
  private Map<String, AccountHolderCapability> capabilities = null;

  public static final String JSON_PROPERTY_CONTACT_DETAILS = "contactDetails";
  private ContactDetails contactDetails;

  public static final String JSON_PROPERTY_DESCRIPTION = "description";
  private String description;

  public static final String JSON_PROPERTY_ID = "id";
  private String id;

  public static final String JSON_PROPERTY_LEGAL_ENTITY_ID = "legalEntityId";
  private String legalEntityId;

  public static final String JSON_PROPERTY_METADATA = "metadata";
  private Map<String, String> metadata = null;

  public static final String JSON_PROPERTY_MIGRATED_ACCOUNT_HOLDER_CODE = "migratedAccountHolderCode";
  private String migratedAccountHolderCode;

  public static final String JSON_PROPERTY_PRIMARY_BALANCE_ACCOUNT = "primaryBalanceAccount";
  private String primaryBalanceAccount;

  public static final String JSON_PROPERTY_REFERENCE = "reference";
  private String reference;

  /**
   * The status of the account holder.  Possible values:    * **active**: The account holder is active. This is the default status when creating an account holder.    * **inactive (Deprecated)**: The account holder is temporarily inactive due to missing KYC details. You can set the account back to active by providing the missing KYC details.    * **suspended**: The account holder is permanently deactivated by Adyen. This action cannot be undone.   * **closed**: The account holder is permanently deactivated by you. This action cannot be undone.
   */
  public enum StatusEnum {
    ACTIVE("active"),
    
    CLOSED("closed"),
    
    INACTIVE("inactive"),
    
    SUSPENDED("suspended");

    private String value;

    StatusEnum(String value) {
      this.value = value;
    }

    @JsonValue
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    @JsonCreator
    public static StatusEnum fromValue(String value) {
      for (StatusEnum b : StatusEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_STATUS = "status";
  private StatusEnum status;

  public static final String JSON_PROPERTY_TIME_ZONE = "timeZone";
  private String timeZone;

  public static final String JSON_PROPERTY_VERIFICATION_DEADLINES = "verificationDeadlines";
  private List<VerificationDeadline> verificationDeadlines = null;

  public AccountHolder() { 
  }

  public AccountHolder balancePlatform(String balancePlatform) {
    this.balancePlatform = balancePlatform;
    return this;
  }

   /**
   * The unique identifier of the [balance platform](https://docs.adyen.com/api-explorer/#/balanceplatform/latest/get/balancePlatforms/{id}__queryParam_id) to which the account holder belongs. Required in the request if your API credentials can be used for multiple balance platforms.
   * @return balancePlatform
  **/
  @ApiModelProperty(value = "The unique identifier of the [balance platform](https://docs.adyen.com/api-explorer/#/balanceplatform/latest/get/balancePlatforms/{id}__queryParam_id) to which the account holder belongs. Required in the request if your API credentials can be used for multiple balance platforms.")
  @JsonProperty(JSON_PROPERTY_BALANCE_PLATFORM)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getBalancePlatform() {
    return balancePlatform;
  }


 /**
  * The unique identifier of the [balance platform](https://docs.adyen.com/api-explorer/#/balanceplatform/latest/get/balancePlatforms/{id}__queryParam_id) to which the account holder belongs. Required in the request if your API credentials can be used for multiple balance platforms.
  *
  * @param balancePlatform
  */ 
  @JsonProperty(JSON_PROPERTY_BALANCE_PLATFORM)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setBalancePlatform(String balancePlatform) {
    this.balancePlatform = balancePlatform;
  }


  public AccountHolder capabilities(Map<String, AccountHolderCapability> capabilities) {
    this.capabilities = capabilities;
    return this;
  }

  public AccountHolder putCapabilitiesItem(String key, AccountHolderCapability capabilitiesItem) {
    if (this.capabilities == null) {
      this.capabilities = new HashMap<>();
    }
    this.capabilities.put(key, capabilitiesItem);
    return this;
  }

   /**
   * Contains key-value pairs that specify the actions that an account holder can do in your platform. The key is a capability required for your integration. For example, **issueCard** for Issuing. The value is an object containing the settings for the capability.
   * @return capabilities
  **/
  @ApiModelProperty(value = "Contains key-value pairs that specify the actions that an account holder can do in your platform. The key is a capability required for your integration. For example, **issueCard** for Issuing. The value is an object containing the settings for the capability.")
  @JsonProperty(JSON_PROPERTY_CAPABILITIES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Map<String, AccountHolderCapability> getCapabilities() {
    return capabilities;
  }


 /**
  * Contains key-value pairs that specify the actions that an account holder can do in your platform. The key is a capability required for your integration. For example, **issueCard** for Issuing. The value is an object containing the settings for the capability.
  *
  * @param capabilities
  */ 
  @JsonProperty(JSON_PROPERTY_CAPABILITIES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCapabilities(Map<String, AccountHolderCapability> capabilities) {
    this.capabilities = capabilities;
  }


  public AccountHolder contactDetails(ContactDetails contactDetails) {
    this.contactDetails = contactDetails;
    return this;
  }

   /**
   * Get contactDetails
   * @return contactDetails
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_CONTACT_DETAILS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public ContactDetails getContactDetails() {
    return contactDetails;
  }


 /**
  * contactDetails
  *
  * @param contactDetails
  */ 
  @JsonProperty(JSON_PROPERTY_CONTACT_DETAILS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setContactDetails(ContactDetails contactDetails) {
    this.contactDetails = contactDetails;
  }


  public AccountHolder description(String description) {
    this.description = description;
    return this;
  }

   /**
   * Your description for the account holder, maximum 300 characters.
   * @return description
  **/
  @ApiModelProperty(value = "Your description for the account holder, maximum 300 characters.")
  @JsonProperty(JSON_PROPERTY_DESCRIPTION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getDescription() {
    return description;
  }


 /**
  * Your description for the account holder, maximum 300 characters.
  *
  * @param description
  */ 
  @JsonProperty(JSON_PROPERTY_DESCRIPTION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDescription(String description) {
    this.description = description;
  }


  public AccountHolder id(String id) {
    this.id = id;
    return this;
  }

   /**
   * The unique identifier of the account holder.
   * @return id
  **/
  @ApiModelProperty(required = true, value = "The unique identifier of the account holder.")
  @JsonProperty(JSON_PROPERTY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getId() {
    return id;
  }


 /**
  * The unique identifier of the account holder.
  *
  * @param id
  */ 
  @JsonProperty(JSON_PROPERTY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setId(String id) {
    this.id = id;
  }


  public AccountHolder legalEntityId(String legalEntityId) {
    this.legalEntityId = legalEntityId;
    return this;
  }

   /**
   * The unique identifier of the [legal entity](https://docs.adyen.com/api-explorer/legalentity/latest/post/legalEntities#responses-200-id) associated with the account holder. Adyen performs a verification process against the legal entity of the account holder.
   * @return legalEntityId
  **/
  @ApiModelProperty(required = true, value = "The unique identifier of the [legal entity](https://docs.adyen.com/api-explorer/legalentity/latest/post/legalEntities#responses-200-id) associated with the account holder. Adyen performs a verification process against the legal entity of the account holder.")
  @JsonProperty(JSON_PROPERTY_LEGAL_ENTITY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getLegalEntityId() {
    return legalEntityId;
  }


 /**
  * The unique identifier of the [legal entity](https://docs.adyen.com/api-explorer/legalentity/latest/post/legalEntities#responses-200-id) associated with the account holder. Adyen performs a verification process against the legal entity of the account holder.
  *
  * @param legalEntityId
  */ 
  @JsonProperty(JSON_PROPERTY_LEGAL_ENTITY_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setLegalEntityId(String legalEntityId) {
    this.legalEntityId = legalEntityId;
  }


  public AccountHolder metadata(Map<String, String> metadata) {
    this.metadata = metadata;
    return this;
  }

  public AccountHolder putMetadataItem(String key, String metadataItem) {
    if (this.metadata == null) {
      this.metadata = new HashMap<>();
    }
    this.metadata.put(key, metadataItem);
    return this;
  }

   /**
   * A set of key and value pairs for general use. The keys do not have specific names and may be used for storing miscellaneous data as desired. &gt; Note that during an update of metadata, the omission of existing key-value pairs will result in the deletion of those key-value pairs.
   * @return metadata
  **/
  @ApiModelProperty(value = "A set of key and value pairs for general use. The keys do not have specific names and may be used for storing miscellaneous data as desired. > Note that during an update of metadata, the omission of existing key-value pairs will result in the deletion of those key-value pairs.")
  @JsonProperty(JSON_PROPERTY_METADATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Map<String, String> getMetadata() {
    return metadata;
  }


 /**
  * A set of key and value pairs for general use. The keys do not have specific names and may be used for storing miscellaneous data as desired. &gt; Note that during an update of metadata, the omission of existing key-value pairs will result in the deletion of those key-value pairs.
  *
  * @param metadata
  */ 
  @JsonProperty(JSON_PROPERTY_METADATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMetadata(Map<String, String> metadata) {
    this.metadata = metadata;
  }


  public AccountHolder migratedAccountHolderCode(String migratedAccountHolderCode) {
    this.migratedAccountHolderCode = migratedAccountHolderCode;
    return this;
  }

   /**
   * The unique identifier of the migrated account holder in the classic integration.
   * @return migratedAccountHolderCode
  **/
  @ApiModelProperty(value = "The unique identifier of the migrated account holder in the classic integration.")
  @JsonProperty(JSON_PROPERTY_MIGRATED_ACCOUNT_HOLDER_CODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getMigratedAccountHolderCode() {
    return migratedAccountHolderCode;
  }


 /**
  * The unique identifier of the migrated account holder in the classic integration.
  *
  * @param migratedAccountHolderCode
  */ 
  @JsonProperty(JSON_PROPERTY_MIGRATED_ACCOUNT_HOLDER_CODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMigratedAccountHolderCode(String migratedAccountHolderCode) {
    this.migratedAccountHolderCode = migratedAccountHolderCode;
  }


  public AccountHolder primaryBalanceAccount(String primaryBalanceAccount) {
    this.primaryBalanceAccount = primaryBalanceAccount;
    return this;
  }

   /**
   * The ID of the account holder&#39;s primary balance account. By default, this is set to the first balance account that you create for the account holder. To assign a different balance account, send a PATCH request.
   * @return primaryBalanceAccount
  **/
  @ApiModelProperty(value = "The ID of the account holder's primary balance account. By default, this is set to the first balance account that you create for the account holder. To assign a different balance account, send a PATCH request.")
  @JsonProperty(JSON_PROPERTY_PRIMARY_BALANCE_ACCOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getPrimaryBalanceAccount() {
    return primaryBalanceAccount;
  }


 /**
  * The ID of the account holder&#39;s primary balance account. By default, this is set to the first balance account that you create for the account holder. To assign a different balance account, send a PATCH request.
  *
  * @param primaryBalanceAccount
  */ 
  @JsonProperty(JSON_PROPERTY_PRIMARY_BALANCE_ACCOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPrimaryBalanceAccount(String primaryBalanceAccount) {
    this.primaryBalanceAccount = primaryBalanceAccount;
  }


  public AccountHolder reference(String reference) {
    this.reference = reference;
    return this;
  }

   /**
   * Your reference for the account holder, maximum 150 characters.
   * @return reference
  **/
  @ApiModelProperty(value = "Your reference for the account holder, maximum 150 characters.")
  @JsonProperty(JSON_PROPERTY_REFERENCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getReference() {
    return reference;
  }


 /**
  * Your reference for the account holder, maximum 150 characters.
  *
  * @param reference
  */ 
  @JsonProperty(JSON_PROPERTY_REFERENCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setReference(String reference) {
    this.reference = reference;
  }


  public AccountHolder status(StatusEnum status) {
    this.status = status;
    return this;
  }

   /**
   * The status of the account holder.  Possible values:    * **active**: The account holder is active. This is the default status when creating an account holder.    * **inactive (Deprecated)**: The account holder is temporarily inactive due to missing KYC details. You can set the account back to active by providing the missing KYC details.    * **suspended**: The account holder is permanently deactivated by Adyen. This action cannot be undone.   * **closed**: The account holder is permanently deactivated by you. This action cannot be undone.
   * @return status
  **/
  @ApiModelProperty(value = "The status of the account holder.  Possible values:    * **active**: The account holder is active. This is the default status when creating an account holder.    * **inactive (Deprecated)**: The account holder is temporarily inactive due to missing KYC details. You can set the account back to active by providing the missing KYC details.    * **suspended**: The account holder is permanently deactivated by Adyen. This action cannot be undone.   * **closed**: The account holder is permanently deactivated by you. This action cannot be undone.")
  @JsonProperty(JSON_PROPERTY_STATUS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public StatusEnum getStatus() {
    return status;
  }


 /**
  * The status of the account holder.  Possible values:    * **active**: The account holder is active. This is the default status when creating an account holder.    * **inactive (Deprecated)**: The account holder is temporarily inactive due to missing KYC details. You can set the account back to active by providing the missing KYC details.    * **suspended**: The account holder is permanently deactivated by Adyen. This action cannot be undone.   * **closed**: The account holder is permanently deactivated by you. This action cannot be undone.
  *
  * @param status
  */ 
  @JsonProperty(JSON_PROPERTY_STATUS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setStatus(StatusEnum status) {
    this.status = status;
  }


  public AccountHolder timeZone(String timeZone) {
    this.timeZone = timeZone;
    return this;
  }

   /**
   * The time zone of the account holder. For example, **Europe/Amsterdam**. Defaults to the time zone of the balance platform if no time zone is set. For possible values, see the [list of time zone codes](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones).
   * @return timeZone
  **/
  @ApiModelProperty(value = "The time zone of the account holder. For example, **Europe/Amsterdam**. Defaults to the time zone of the balance platform if no time zone is set. For possible values, see the [list of time zone codes](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones).")
  @JsonProperty(JSON_PROPERTY_TIME_ZONE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getTimeZone() {
    return timeZone;
  }


 /**
  * The time zone of the account holder. For example, **Europe/Amsterdam**. Defaults to the time zone of the balance platform if no time zone is set. For possible values, see the [list of time zone codes](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones).
  *
  * @param timeZone
  */ 
  @JsonProperty(JSON_PROPERTY_TIME_ZONE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setTimeZone(String timeZone) {
    this.timeZone = timeZone;
  }


  public AccountHolder verificationDeadlines(List<VerificationDeadline> verificationDeadlines) {
    this.verificationDeadlines = verificationDeadlines;
    return this;
  }

  public AccountHolder addVerificationDeadlinesItem(VerificationDeadline verificationDeadlinesItem) {
    if (this.verificationDeadlines == null) {
      this.verificationDeadlines = new ArrayList<>();
    }
    this.verificationDeadlines.add(verificationDeadlinesItem);
    return this;
  }

   /**
   * List of verification deadlines and the capabilities that will be disallowed if verification errors are not resolved.
   * @return verificationDeadlines
  **/
  @ApiModelProperty(value = "List of verification deadlines and the capabilities that will be disallowed if verification errors are not resolved.")
  @JsonProperty(JSON_PROPERTY_VERIFICATION_DEADLINES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<VerificationDeadline> getVerificationDeadlines() {
    return verificationDeadlines;
  }


 /**
  * List of verification deadlines and the capabilities that will be disallowed if verification errors are not resolved.
  *
  * @param verificationDeadlines
  */ 
  @JsonProperty(JSON_PROPERTY_VERIFICATION_DEADLINES)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setVerificationDeadlines(List<VerificationDeadline> verificationDeadlines) {
    this.verificationDeadlines = verificationDeadlines;
  }


  /**
   * Return true if this AccountHolder object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AccountHolder accountHolder = (AccountHolder) o;
    return Objects.equals(this.balancePlatform, accountHolder.balancePlatform) &&
        Objects.equals(this.capabilities, accountHolder.capabilities) &&
        Objects.equals(this.contactDetails, accountHolder.contactDetails) &&
        Objects.equals(this.description, accountHolder.description) &&
        Objects.equals(this.id, accountHolder.id) &&
        Objects.equals(this.legalEntityId, accountHolder.legalEntityId) &&
        Objects.equals(this.metadata, accountHolder.metadata) &&
        Objects.equals(this.migratedAccountHolderCode, accountHolder.migratedAccountHolderCode) &&
        Objects.equals(this.primaryBalanceAccount, accountHolder.primaryBalanceAccount) &&
        Objects.equals(this.reference, accountHolder.reference) &&
        Objects.equals(this.status, accountHolder.status) &&
        Objects.equals(this.timeZone, accountHolder.timeZone) &&
        Objects.equals(this.verificationDeadlines, accountHolder.verificationDeadlines);
  }

  @Override
  public int hashCode() {
    return Objects.hash(balancePlatform, capabilities, contactDetails, description, id, legalEntityId, metadata, migratedAccountHolderCode, primaryBalanceAccount, reference, status, timeZone, verificationDeadlines);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AccountHolder {\n");
    sb.append("    balancePlatform: ").append(toIndentedString(balancePlatform)).append("\n");
    sb.append("    capabilities: ").append(toIndentedString(capabilities)).append("\n");
    sb.append("    contactDetails: ").append(toIndentedString(contactDetails)).append("\n");
    sb.append("    description: ").append(toIndentedString(description)).append("\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    legalEntityId: ").append(toIndentedString(legalEntityId)).append("\n");
    sb.append("    metadata: ").append(toIndentedString(metadata)).append("\n");
    sb.append("    migratedAccountHolderCode: ").append(toIndentedString(migratedAccountHolderCode)).append("\n");
    sb.append("    primaryBalanceAccount: ").append(toIndentedString(primaryBalanceAccount)).append("\n");
    sb.append("    reference: ").append(toIndentedString(reference)).append("\n");
    sb.append("    status: ").append(toIndentedString(status)).append("\n");
    sb.append("    timeZone: ").append(toIndentedString(timeZone)).append("\n");
    sb.append("    verificationDeadlines: ").append(toIndentedString(verificationDeadlines)).append("\n");
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
   * Create an instance of AccountHolder given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of AccountHolder
   * @throws JsonProcessingException if the JSON string is invalid with respect to AccountHolder
   */
  public static AccountHolder fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, AccountHolder.class);
  }
/**
  * Convert an instance of AccountHolder to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

