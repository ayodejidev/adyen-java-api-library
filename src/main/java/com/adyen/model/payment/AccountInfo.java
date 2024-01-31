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
import java.time.OffsetDateTime;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * AccountInfo
 */
@JsonPropertyOrder({
  AccountInfo.JSON_PROPERTY_ACCOUNT_AGE_INDICATOR,
  AccountInfo.JSON_PROPERTY_ACCOUNT_CHANGE_DATE,
  AccountInfo.JSON_PROPERTY_ACCOUNT_CHANGE_INDICATOR,
  AccountInfo.JSON_PROPERTY_ACCOUNT_CREATION_DATE,
  AccountInfo.JSON_PROPERTY_ACCOUNT_TYPE,
  AccountInfo.JSON_PROPERTY_ADD_CARD_ATTEMPTS_DAY,
  AccountInfo.JSON_PROPERTY_DELIVERY_ADDRESS_USAGE_DATE,
  AccountInfo.JSON_PROPERTY_DELIVERY_ADDRESS_USAGE_INDICATOR,
  AccountInfo.JSON_PROPERTY_HOME_PHONE,
  AccountInfo.JSON_PROPERTY_MOBILE_PHONE,
  AccountInfo.JSON_PROPERTY_PASSWORD_CHANGE_DATE,
  AccountInfo.JSON_PROPERTY_PASSWORD_CHANGE_INDICATOR,
  AccountInfo.JSON_PROPERTY_PAST_TRANSACTIONS_DAY,
  AccountInfo.JSON_PROPERTY_PAST_TRANSACTIONS_YEAR,
  AccountInfo.JSON_PROPERTY_PAYMENT_ACCOUNT_AGE,
  AccountInfo.JSON_PROPERTY_PAYMENT_ACCOUNT_INDICATOR,
  AccountInfo.JSON_PROPERTY_PURCHASES_LAST6_MONTHS,
  AccountInfo.JSON_PROPERTY_SUSPICIOUS_ACTIVITY,
  AccountInfo.JSON_PROPERTY_WORK_PHONE
})

public class AccountInfo {
  /**
   * Indicator for the length of time since this shopper account was created in the merchant&#39;s environment. Allowed values: * notApplicable * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
   */
  public enum AccountAgeIndicatorEnum {
    NOTAPPLICABLE("notApplicable"),
    
    THISTRANSACTION("thisTransaction"),
    
    LESSTHAN30DAYS("lessThan30Days"),
    
    FROM30TO60DAYS("from30To60Days"),
    
    MORETHAN60DAYS("moreThan60Days");

    private String value;

    AccountAgeIndicatorEnum(String value) {
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
    public static AccountAgeIndicatorEnum fromValue(String value) {
      for (AccountAgeIndicatorEnum b : AccountAgeIndicatorEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_ACCOUNT_AGE_INDICATOR = "accountAgeIndicator";
  private AccountAgeIndicatorEnum accountAgeIndicator;

  public static final String JSON_PROPERTY_ACCOUNT_CHANGE_DATE = "accountChangeDate";
  private OffsetDateTime accountChangeDate;

  /**
   * Indicator for the length of time since the shopper&#39;s account was last updated. Allowed values: * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
   */
  public enum AccountChangeIndicatorEnum {
    THISTRANSACTION("thisTransaction"),
    
    LESSTHAN30DAYS("lessThan30Days"),
    
    FROM30TO60DAYS("from30To60Days"),
    
    MORETHAN60DAYS("moreThan60Days");

    private String value;

    AccountChangeIndicatorEnum(String value) {
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
    public static AccountChangeIndicatorEnum fromValue(String value) {
      for (AccountChangeIndicatorEnum b : AccountChangeIndicatorEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_ACCOUNT_CHANGE_INDICATOR = "accountChangeIndicator";
  private AccountChangeIndicatorEnum accountChangeIndicator;

  public static final String JSON_PROPERTY_ACCOUNT_CREATION_DATE = "accountCreationDate";
  private OffsetDateTime accountCreationDate;

  /**
   * Indicates the type of account. For example, for a multi-account card product. Allowed values: * notApplicable * credit * debit
   */
  public enum AccountTypeEnum {
    NOTAPPLICABLE("notApplicable"),
    
    CREDIT("credit"),
    
    DEBIT("debit");

    private String value;

    AccountTypeEnum(String value) {
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
    public static AccountTypeEnum fromValue(String value) {
      for (AccountTypeEnum b : AccountTypeEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_ACCOUNT_TYPE = "accountType";
  private AccountTypeEnum accountType;

  public static final String JSON_PROPERTY_ADD_CARD_ATTEMPTS_DAY = "addCardAttemptsDay";
  private Integer addCardAttemptsDay;

  public static final String JSON_PROPERTY_DELIVERY_ADDRESS_USAGE_DATE = "deliveryAddressUsageDate";
  private OffsetDateTime deliveryAddressUsageDate;

  /**
   * Indicator for the length of time since this delivery address was first used. Allowed values: * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
   */
  public enum DeliveryAddressUsageIndicatorEnum {
    THISTRANSACTION("thisTransaction"),
    
    LESSTHAN30DAYS("lessThan30Days"),
    
    FROM30TO60DAYS("from30To60Days"),
    
    MORETHAN60DAYS("moreThan60Days");

    private String value;

    DeliveryAddressUsageIndicatorEnum(String value) {
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
    public static DeliveryAddressUsageIndicatorEnum fromValue(String value) {
      for (DeliveryAddressUsageIndicatorEnum b : DeliveryAddressUsageIndicatorEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_DELIVERY_ADDRESS_USAGE_INDICATOR = "deliveryAddressUsageIndicator";
  private DeliveryAddressUsageIndicatorEnum deliveryAddressUsageIndicator;

  public static final String JSON_PROPERTY_HOME_PHONE = "homePhone";
  private String homePhone;

  public static final String JSON_PROPERTY_MOBILE_PHONE = "mobilePhone";
  private String mobilePhone;

  public static final String JSON_PROPERTY_PASSWORD_CHANGE_DATE = "passwordChangeDate";
  private OffsetDateTime passwordChangeDate;

  /**
   * Indicator when the shopper has changed their password. Allowed values: * notApplicable * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
   */
  public enum PasswordChangeIndicatorEnum {
    NOTAPPLICABLE("notApplicable"),
    
    THISTRANSACTION("thisTransaction"),
    
    LESSTHAN30DAYS("lessThan30Days"),
    
    FROM30TO60DAYS("from30To60Days"),
    
    MORETHAN60DAYS("moreThan60Days");

    private String value;

    PasswordChangeIndicatorEnum(String value) {
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
    public static PasswordChangeIndicatorEnum fromValue(String value) {
      for (PasswordChangeIndicatorEnum b : PasswordChangeIndicatorEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_PASSWORD_CHANGE_INDICATOR = "passwordChangeIndicator";
  private PasswordChangeIndicatorEnum passwordChangeIndicator;

  public static final String JSON_PROPERTY_PAST_TRANSACTIONS_DAY = "pastTransactionsDay";
  private Integer pastTransactionsDay;

  public static final String JSON_PROPERTY_PAST_TRANSACTIONS_YEAR = "pastTransactionsYear";
  private Integer pastTransactionsYear;

  public static final String JSON_PROPERTY_PAYMENT_ACCOUNT_AGE = "paymentAccountAge";
  private OffsetDateTime paymentAccountAge;

  /**
   * Indicator for the length of time since this payment method was added to this shopper&#39;s account. Allowed values: * notApplicable * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
   */
  public enum PaymentAccountIndicatorEnum {
    NOTAPPLICABLE("notApplicable"),
    
    THISTRANSACTION("thisTransaction"),
    
    LESSTHAN30DAYS("lessThan30Days"),
    
    FROM30TO60DAYS("from30To60Days"),
    
    MORETHAN60DAYS("moreThan60Days");

    private String value;

    PaymentAccountIndicatorEnum(String value) {
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
    public static PaymentAccountIndicatorEnum fromValue(String value) {
      for (PaymentAccountIndicatorEnum b : PaymentAccountIndicatorEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_PAYMENT_ACCOUNT_INDICATOR = "paymentAccountIndicator";
  private PaymentAccountIndicatorEnum paymentAccountIndicator;

  public static final String JSON_PROPERTY_PURCHASES_LAST6_MONTHS = "purchasesLast6Months";
  private Integer purchasesLast6Months;

  public static final String JSON_PROPERTY_SUSPICIOUS_ACTIVITY = "suspiciousActivity";
  private Boolean suspiciousActivity;

  public static final String JSON_PROPERTY_WORK_PHONE = "workPhone";
  private String workPhone;

  public AccountInfo() { 
  }

  public AccountInfo accountAgeIndicator(AccountAgeIndicatorEnum accountAgeIndicator) {
    this.accountAgeIndicator = accountAgeIndicator;
    return this;
  }

   /**
   * Indicator for the length of time since this shopper account was created in the merchant&#39;s environment. Allowed values: * notApplicable * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
   * @return accountAgeIndicator
  **/
  @ApiModelProperty(value = "Indicator for the length of time since this shopper account was created in the merchant's environment. Allowed values: * notApplicable * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days")
  @JsonProperty(JSON_PROPERTY_ACCOUNT_AGE_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public AccountAgeIndicatorEnum getAccountAgeIndicator() {
    return accountAgeIndicator;
  }


 /**
  * Indicator for the length of time since this shopper account was created in the merchant&#39;s environment. Allowed values: * notApplicable * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
  *
  * @param accountAgeIndicator
  */ 
  @JsonProperty(JSON_PROPERTY_ACCOUNT_AGE_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAccountAgeIndicator(AccountAgeIndicatorEnum accountAgeIndicator) {
    this.accountAgeIndicator = accountAgeIndicator;
  }


  public AccountInfo accountChangeDate(OffsetDateTime accountChangeDate) {
    this.accountChangeDate = accountChangeDate;
    return this;
  }

   /**
   * Date when the shopper&#39;s account was last changed.
   * @return accountChangeDate
  **/
  @ApiModelProperty(value = "Date when the shopper's account was last changed.")
  @JsonProperty(JSON_PROPERTY_ACCOUNT_CHANGE_DATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public OffsetDateTime getAccountChangeDate() {
    return accountChangeDate;
  }


 /**
  * Date when the shopper&#39;s account was last changed.
  *
  * @param accountChangeDate
  */ 
  @JsonProperty(JSON_PROPERTY_ACCOUNT_CHANGE_DATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAccountChangeDate(OffsetDateTime accountChangeDate) {
    this.accountChangeDate = accountChangeDate;
  }


  public AccountInfo accountChangeIndicator(AccountChangeIndicatorEnum accountChangeIndicator) {
    this.accountChangeIndicator = accountChangeIndicator;
    return this;
  }

   /**
   * Indicator for the length of time since the shopper&#39;s account was last updated. Allowed values: * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
   * @return accountChangeIndicator
  **/
  @ApiModelProperty(value = "Indicator for the length of time since the shopper's account was last updated. Allowed values: * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days")
  @JsonProperty(JSON_PROPERTY_ACCOUNT_CHANGE_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public AccountChangeIndicatorEnum getAccountChangeIndicator() {
    return accountChangeIndicator;
  }


 /**
  * Indicator for the length of time since the shopper&#39;s account was last updated. Allowed values: * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
  *
  * @param accountChangeIndicator
  */ 
  @JsonProperty(JSON_PROPERTY_ACCOUNT_CHANGE_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAccountChangeIndicator(AccountChangeIndicatorEnum accountChangeIndicator) {
    this.accountChangeIndicator = accountChangeIndicator;
  }


  public AccountInfo accountCreationDate(OffsetDateTime accountCreationDate) {
    this.accountCreationDate = accountCreationDate;
    return this;
  }

   /**
   * Date when the shopper&#39;s account was created.
   * @return accountCreationDate
  **/
  @ApiModelProperty(value = "Date when the shopper's account was created.")
  @JsonProperty(JSON_PROPERTY_ACCOUNT_CREATION_DATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public OffsetDateTime getAccountCreationDate() {
    return accountCreationDate;
  }


 /**
  * Date when the shopper&#39;s account was created.
  *
  * @param accountCreationDate
  */ 
  @JsonProperty(JSON_PROPERTY_ACCOUNT_CREATION_DATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAccountCreationDate(OffsetDateTime accountCreationDate) {
    this.accountCreationDate = accountCreationDate;
  }


  public AccountInfo accountType(AccountTypeEnum accountType) {
    this.accountType = accountType;
    return this;
  }

   /**
   * Indicates the type of account. For example, for a multi-account card product. Allowed values: * notApplicable * credit * debit
   * @return accountType
  **/
  @ApiModelProperty(value = "Indicates the type of account. For example, for a multi-account card product. Allowed values: * notApplicable * credit * debit")
  @JsonProperty(JSON_PROPERTY_ACCOUNT_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public AccountTypeEnum getAccountType() {
    return accountType;
  }


 /**
  * Indicates the type of account. For example, for a multi-account card product. Allowed values: * notApplicable * credit * debit
  *
  * @param accountType
  */ 
  @JsonProperty(JSON_PROPERTY_ACCOUNT_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAccountType(AccountTypeEnum accountType) {
    this.accountType = accountType;
  }


  public AccountInfo addCardAttemptsDay(Integer addCardAttemptsDay) {
    this.addCardAttemptsDay = addCardAttemptsDay;
    return this;
  }

   /**
   * Number of attempts the shopper tried to add a card to their account in the last day.
   * @return addCardAttemptsDay
  **/
  @ApiModelProperty(value = "Number of attempts the shopper tried to add a card to their account in the last day.")
  @JsonProperty(JSON_PROPERTY_ADD_CARD_ATTEMPTS_DAY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Integer getAddCardAttemptsDay() {
    return addCardAttemptsDay;
  }


 /**
  * Number of attempts the shopper tried to add a card to their account in the last day.
  *
  * @param addCardAttemptsDay
  */ 
  @JsonProperty(JSON_PROPERTY_ADD_CARD_ATTEMPTS_DAY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAddCardAttemptsDay(Integer addCardAttemptsDay) {
    this.addCardAttemptsDay = addCardAttemptsDay;
  }


  public AccountInfo deliveryAddressUsageDate(OffsetDateTime deliveryAddressUsageDate) {
    this.deliveryAddressUsageDate = deliveryAddressUsageDate;
    return this;
  }

   /**
   * Date the selected delivery address was first used.
   * @return deliveryAddressUsageDate
  **/
  @ApiModelProperty(value = "Date the selected delivery address was first used.")
  @JsonProperty(JSON_PROPERTY_DELIVERY_ADDRESS_USAGE_DATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public OffsetDateTime getDeliveryAddressUsageDate() {
    return deliveryAddressUsageDate;
  }


 /**
  * Date the selected delivery address was first used.
  *
  * @param deliveryAddressUsageDate
  */ 
  @JsonProperty(JSON_PROPERTY_DELIVERY_ADDRESS_USAGE_DATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDeliveryAddressUsageDate(OffsetDateTime deliveryAddressUsageDate) {
    this.deliveryAddressUsageDate = deliveryAddressUsageDate;
  }


  public AccountInfo deliveryAddressUsageIndicator(DeliveryAddressUsageIndicatorEnum deliveryAddressUsageIndicator) {
    this.deliveryAddressUsageIndicator = deliveryAddressUsageIndicator;
    return this;
  }

   /**
   * Indicator for the length of time since this delivery address was first used. Allowed values: * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
   * @return deliveryAddressUsageIndicator
  **/
  @ApiModelProperty(value = "Indicator for the length of time since this delivery address was first used. Allowed values: * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days")
  @JsonProperty(JSON_PROPERTY_DELIVERY_ADDRESS_USAGE_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public DeliveryAddressUsageIndicatorEnum getDeliveryAddressUsageIndicator() {
    return deliveryAddressUsageIndicator;
  }


 /**
  * Indicator for the length of time since this delivery address was first used. Allowed values: * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
  *
  * @param deliveryAddressUsageIndicator
  */ 
  @JsonProperty(JSON_PROPERTY_DELIVERY_ADDRESS_USAGE_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDeliveryAddressUsageIndicator(DeliveryAddressUsageIndicatorEnum deliveryAddressUsageIndicator) {
    this.deliveryAddressUsageIndicator = deliveryAddressUsageIndicator;
  }


  public AccountInfo homePhone(String homePhone) {
    this.homePhone = homePhone;
    return this;
  }

   /**
   * Shopper&#39;s home phone number (including the country code).
   * @return homePhone
   * @deprecated
  **/
  @Deprecated
  @ApiModelProperty(value = "Shopper's home phone number (including the country code).")
  @JsonProperty(JSON_PROPERTY_HOME_PHONE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getHomePhone() {
    return homePhone;
  }


 /**
  * Shopper&#39;s home phone number (including the country code).
  *
  * @param homePhone
  */ 
  @Deprecated
  @JsonProperty(JSON_PROPERTY_HOME_PHONE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setHomePhone(String homePhone) {
    this.homePhone = homePhone;
  }


  public AccountInfo mobilePhone(String mobilePhone) {
    this.mobilePhone = mobilePhone;
    return this;
  }

   /**
   * Shopper&#39;s mobile phone number (including the country code).
   * @return mobilePhone
   * @deprecated
  **/
  @Deprecated
  @ApiModelProperty(value = "Shopper's mobile phone number (including the country code).")
  @JsonProperty(JSON_PROPERTY_MOBILE_PHONE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getMobilePhone() {
    return mobilePhone;
  }


 /**
  * Shopper&#39;s mobile phone number (including the country code).
  *
  * @param mobilePhone
  */ 
  @Deprecated
  @JsonProperty(JSON_PROPERTY_MOBILE_PHONE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMobilePhone(String mobilePhone) {
    this.mobilePhone = mobilePhone;
  }


  public AccountInfo passwordChangeDate(OffsetDateTime passwordChangeDate) {
    this.passwordChangeDate = passwordChangeDate;
    return this;
  }

   /**
   * Date when the shopper last changed their password.
   * @return passwordChangeDate
  **/
  @ApiModelProperty(value = "Date when the shopper last changed their password.")
  @JsonProperty(JSON_PROPERTY_PASSWORD_CHANGE_DATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public OffsetDateTime getPasswordChangeDate() {
    return passwordChangeDate;
  }


 /**
  * Date when the shopper last changed their password.
  *
  * @param passwordChangeDate
  */ 
  @JsonProperty(JSON_PROPERTY_PASSWORD_CHANGE_DATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPasswordChangeDate(OffsetDateTime passwordChangeDate) {
    this.passwordChangeDate = passwordChangeDate;
  }


  public AccountInfo passwordChangeIndicator(PasswordChangeIndicatorEnum passwordChangeIndicator) {
    this.passwordChangeIndicator = passwordChangeIndicator;
    return this;
  }

   /**
   * Indicator when the shopper has changed their password. Allowed values: * notApplicable * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
   * @return passwordChangeIndicator
  **/
  @ApiModelProperty(value = "Indicator when the shopper has changed their password. Allowed values: * notApplicable * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days")
  @JsonProperty(JSON_PROPERTY_PASSWORD_CHANGE_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public PasswordChangeIndicatorEnum getPasswordChangeIndicator() {
    return passwordChangeIndicator;
  }


 /**
  * Indicator when the shopper has changed their password. Allowed values: * notApplicable * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
  *
  * @param passwordChangeIndicator
  */ 
  @JsonProperty(JSON_PROPERTY_PASSWORD_CHANGE_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPasswordChangeIndicator(PasswordChangeIndicatorEnum passwordChangeIndicator) {
    this.passwordChangeIndicator = passwordChangeIndicator;
  }


  public AccountInfo pastTransactionsDay(Integer pastTransactionsDay) {
    this.pastTransactionsDay = pastTransactionsDay;
    return this;
  }

   /**
   * Number of all transactions (successful and abandoned) from this shopper in the past 24 hours.
   * @return pastTransactionsDay
  **/
  @ApiModelProperty(value = "Number of all transactions (successful and abandoned) from this shopper in the past 24 hours.")
  @JsonProperty(JSON_PROPERTY_PAST_TRANSACTIONS_DAY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Integer getPastTransactionsDay() {
    return pastTransactionsDay;
  }


 /**
  * Number of all transactions (successful and abandoned) from this shopper in the past 24 hours.
  *
  * @param pastTransactionsDay
  */ 
  @JsonProperty(JSON_PROPERTY_PAST_TRANSACTIONS_DAY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPastTransactionsDay(Integer pastTransactionsDay) {
    this.pastTransactionsDay = pastTransactionsDay;
  }


  public AccountInfo pastTransactionsYear(Integer pastTransactionsYear) {
    this.pastTransactionsYear = pastTransactionsYear;
    return this;
  }

   /**
   * Number of all transactions (successful and abandoned) from this shopper in the past year.
   * @return pastTransactionsYear
  **/
  @ApiModelProperty(value = "Number of all transactions (successful and abandoned) from this shopper in the past year.")
  @JsonProperty(JSON_PROPERTY_PAST_TRANSACTIONS_YEAR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Integer getPastTransactionsYear() {
    return pastTransactionsYear;
  }


 /**
  * Number of all transactions (successful and abandoned) from this shopper in the past year.
  *
  * @param pastTransactionsYear
  */ 
  @JsonProperty(JSON_PROPERTY_PAST_TRANSACTIONS_YEAR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPastTransactionsYear(Integer pastTransactionsYear) {
    this.pastTransactionsYear = pastTransactionsYear;
  }


  public AccountInfo paymentAccountAge(OffsetDateTime paymentAccountAge) {
    this.paymentAccountAge = paymentAccountAge;
    return this;
  }

   /**
   * Date this payment method was added to the shopper&#39;s account.
   * @return paymentAccountAge
  **/
  @ApiModelProperty(value = "Date this payment method was added to the shopper's account.")
  @JsonProperty(JSON_PROPERTY_PAYMENT_ACCOUNT_AGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public OffsetDateTime getPaymentAccountAge() {
    return paymentAccountAge;
  }


 /**
  * Date this payment method was added to the shopper&#39;s account.
  *
  * @param paymentAccountAge
  */ 
  @JsonProperty(JSON_PROPERTY_PAYMENT_ACCOUNT_AGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPaymentAccountAge(OffsetDateTime paymentAccountAge) {
    this.paymentAccountAge = paymentAccountAge;
  }


  public AccountInfo paymentAccountIndicator(PaymentAccountIndicatorEnum paymentAccountIndicator) {
    this.paymentAccountIndicator = paymentAccountIndicator;
    return this;
  }

   /**
   * Indicator for the length of time since this payment method was added to this shopper&#39;s account. Allowed values: * notApplicable * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
   * @return paymentAccountIndicator
  **/
  @ApiModelProperty(value = "Indicator for the length of time since this payment method was added to this shopper's account. Allowed values: * notApplicable * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days")
  @JsonProperty(JSON_PROPERTY_PAYMENT_ACCOUNT_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public PaymentAccountIndicatorEnum getPaymentAccountIndicator() {
    return paymentAccountIndicator;
  }


 /**
  * Indicator for the length of time since this payment method was added to this shopper&#39;s account. Allowed values: * notApplicable * thisTransaction * lessThan30Days * from30To60Days * moreThan60Days
  *
  * @param paymentAccountIndicator
  */ 
  @JsonProperty(JSON_PROPERTY_PAYMENT_ACCOUNT_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPaymentAccountIndicator(PaymentAccountIndicatorEnum paymentAccountIndicator) {
    this.paymentAccountIndicator = paymentAccountIndicator;
  }


  public AccountInfo purchasesLast6Months(Integer purchasesLast6Months) {
    this.purchasesLast6Months = purchasesLast6Months;
    return this;
  }

   /**
   * Number of successful purchases in the last six months.
   * @return purchasesLast6Months
  **/
  @ApiModelProperty(value = "Number of successful purchases in the last six months.")
  @JsonProperty(JSON_PROPERTY_PURCHASES_LAST6_MONTHS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Integer getPurchasesLast6Months() {
    return purchasesLast6Months;
  }


 /**
  * Number of successful purchases in the last six months.
  *
  * @param purchasesLast6Months
  */ 
  @JsonProperty(JSON_PROPERTY_PURCHASES_LAST6_MONTHS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPurchasesLast6Months(Integer purchasesLast6Months) {
    this.purchasesLast6Months = purchasesLast6Months;
  }


  public AccountInfo suspiciousActivity(Boolean suspiciousActivity) {
    this.suspiciousActivity = suspiciousActivity;
    return this;
  }

   /**
   * Whether suspicious activity was recorded on this account.
   * @return suspiciousActivity
  **/
  @ApiModelProperty(value = "Whether suspicious activity was recorded on this account.")
  @JsonProperty(JSON_PROPERTY_SUSPICIOUS_ACTIVITY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getSuspiciousActivity() {
    return suspiciousActivity;
  }


 /**
  * Whether suspicious activity was recorded on this account.
  *
  * @param suspiciousActivity
  */ 
  @JsonProperty(JSON_PROPERTY_SUSPICIOUS_ACTIVITY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setSuspiciousActivity(Boolean suspiciousActivity) {
    this.suspiciousActivity = suspiciousActivity;
  }


  public AccountInfo workPhone(String workPhone) {
    this.workPhone = workPhone;
    return this;
  }

   /**
   * Shopper&#39;s work phone number (including the country code).
   * @return workPhone
   * @deprecated
  **/
  @Deprecated
  @ApiModelProperty(value = "Shopper's work phone number (including the country code).")
  @JsonProperty(JSON_PROPERTY_WORK_PHONE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getWorkPhone() {
    return workPhone;
  }


 /**
  * Shopper&#39;s work phone number (including the country code).
  *
  * @param workPhone
  */ 
  @Deprecated
  @JsonProperty(JSON_PROPERTY_WORK_PHONE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setWorkPhone(String workPhone) {
    this.workPhone = workPhone;
  }


  /**
   * Return true if this AccountInfo object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AccountInfo accountInfo = (AccountInfo) o;
    return Objects.equals(this.accountAgeIndicator, accountInfo.accountAgeIndicator) &&
        Objects.equals(this.accountChangeDate, accountInfo.accountChangeDate) &&
        Objects.equals(this.accountChangeIndicator, accountInfo.accountChangeIndicator) &&
        Objects.equals(this.accountCreationDate, accountInfo.accountCreationDate) &&
        Objects.equals(this.accountType, accountInfo.accountType) &&
        Objects.equals(this.addCardAttemptsDay, accountInfo.addCardAttemptsDay) &&
        Objects.equals(this.deliveryAddressUsageDate, accountInfo.deliveryAddressUsageDate) &&
        Objects.equals(this.deliveryAddressUsageIndicator, accountInfo.deliveryAddressUsageIndicator) &&
        Objects.equals(this.homePhone, accountInfo.homePhone) &&
        Objects.equals(this.mobilePhone, accountInfo.mobilePhone) &&
        Objects.equals(this.passwordChangeDate, accountInfo.passwordChangeDate) &&
        Objects.equals(this.passwordChangeIndicator, accountInfo.passwordChangeIndicator) &&
        Objects.equals(this.pastTransactionsDay, accountInfo.pastTransactionsDay) &&
        Objects.equals(this.pastTransactionsYear, accountInfo.pastTransactionsYear) &&
        Objects.equals(this.paymentAccountAge, accountInfo.paymentAccountAge) &&
        Objects.equals(this.paymentAccountIndicator, accountInfo.paymentAccountIndicator) &&
        Objects.equals(this.purchasesLast6Months, accountInfo.purchasesLast6Months) &&
        Objects.equals(this.suspiciousActivity, accountInfo.suspiciousActivity) &&
        Objects.equals(this.workPhone, accountInfo.workPhone);
  }

  @Override
  public int hashCode() {
    return Objects.hash(accountAgeIndicator, accountChangeDate, accountChangeIndicator, accountCreationDate, accountType, addCardAttemptsDay, deliveryAddressUsageDate, deliveryAddressUsageIndicator, homePhone, mobilePhone, passwordChangeDate, passwordChangeIndicator, pastTransactionsDay, pastTransactionsYear, paymentAccountAge, paymentAccountIndicator, purchasesLast6Months, suspiciousActivity, workPhone);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AccountInfo {\n");
    sb.append("    accountAgeIndicator: ").append(toIndentedString(accountAgeIndicator)).append("\n");
    sb.append("    accountChangeDate: ").append(toIndentedString(accountChangeDate)).append("\n");
    sb.append("    accountChangeIndicator: ").append(toIndentedString(accountChangeIndicator)).append("\n");
    sb.append("    accountCreationDate: ").append(toIndentedString(accountCreationDate)).append("\n");
    sb.append("    accountType: ").append(toIndentedString(accountType)).append("\n");
    sb.append("    addCardAttemptsDay: ").append(toIndentedString(addCardAttemptsDay)).append("\n");
    sb.append("    deliveryAddressUsageDate: ").append(toIndentedString(deliveryAddressUsageDate)).append("\n");
    sb.append("    deliveryAddressUsageIndicator: ").append(toIndentedString(deliveryAddressUsageIndicator)).append("\n");
    sb.append("    homePhone: ").append(toIndentedString(homePhone)).append("\n");
    sb.append("    mobilePhone: ").append(toIndentedString(mobilePhone)).append("\n");
    sb.append("    passwordChangeDate: ").append(toIndentedString(passwordChangeDate)).append("\n");
    sb.append("    passwordChangeIndicator: ").append(toIndentedString(passwordChangeIndicator)).append("\n");
    sb.append("    pastTransactionsDay: ").append(toIndentedString(pastTransactionsDay)).append("\n");
    sb.append("    pastTransactionsYear: ").append(toIndentedString(pastTransactionsYear)).append("\n");
    sb.append("    paymentAccountAge: ").append(toIndentedString(paymentAccountAge)).append("\n");
    sb.append("    paymentAccountIndicator: ").append(toIndentedString(paymentAccountIndicator)).append("\n");
    sb.append("    purchasesLast6Months: ").append(toIndentedString(purchasesLast6Months)).append("\n");
    sb.append("    suspiciousActivity: ").append(toIndentedString(suspiciousActivity)).append("\n");
    sb.append("    workPhone: ").append(toIndentedString(workPhone)).append("\n");
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
   * Create an instance of AccountInfo given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of AccountInfo
   * @throws JsonProcessingException if the JSON string is invalid with respect to AccountInfo
   */
  public static AccountInfo fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, AccountInfo.class);
  }
/**
  * Convert an instance of AccountInfo to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

