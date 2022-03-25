use std::fmt::{Debug, Formatter, Result as FormatterResult};
use std::marker::PhantomData;
use std::str;

use chrono::{DateTime, Utc};
use serde::de::{Deserialize, DeserializeOwned, Deserializer, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::helpers::FlattenFilter;
use crate::types::helpers::{split_language_tag_key, timestamp_to_utc, utc_to_seconds};
use crate::types::{LocalizedClaim, Timestamp};
use crate::{
    AddressCountry, AddressLocality, AddressPostalCode, AddressRegion, EndUserBirthday,
    EndUserEmail, EndUserFamilyName, EndUserGivenName, EndUserMiddleName, EndUserName,
    EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserProfileUrl, EndUserTimezone,
    EndUserUsername, EndUserWebsiteUrl, FormattedAddress, LanguageTag, StreetAddress,
    SubjectIdentifier,
};

///
/// Additional claims beyond the set of Standard Claims defined by OpenID Connect Core.
///
pub trait AdditionalClaims: Debug + DeserializeOwned + Serialize + 'static {}

///
/// No additional claims.
///
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
// In order to support serde flatten, this must be an empty struct rather than an empty
// tuple struct.
pub struct EmptyAdditionalClaims {}
impl AdditionalClaims for EmptyAdditionalClaims {}

///
/// Address claims.
///
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct AddressClaim {
    ///
    /// Full mailing address, formatted for display or use on a mailing label.
    ///
    /// This field MAY contain multiple lines, separated by newlines. Newlines can be represented
    /// either as a carriage return/line feed pair (`\r\n`) or as a single line feed character
    /// (`\n`).
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<FormattedAddress>,
    ///
    /// Full street address component, which MAY include house number, street name, Post Office Box,
    /// and multi-line extended street address information.
    ///
    /// This field MAY contain multiple lines, separated by newlines. Newlines can be represented
    /// either as a carriage return/line feed pair (`\r\n`) or as a single line feed character
    /// (`\n`).
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<StreetAddress>,
    ///
    /// City or locality component.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<AddressLocality>,
    ///
    /// State, province, prefecture, or region component.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<AddressRegion>,
    ///
    /// Zip code or postal code component.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<AddressPostalCode>,
    ///
    /// Country name component.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<AddressCountry>,
}

///
/// Gender claim.
///
pub trait GenderClaim: Clone + Debug + DeserializeOwned + Serialize + 'static {}

///
/// Standard Claims defined by OpenID Connect Core.
///
#[derive(Clone, Debug, PartialEq)]
pub struct StandardClaims<GC>
where
    GC: GenderClaim,
{
    pub(crate) sub: SubjectIdentifier,
    pub(crate) name: Option<LocalizedClaim<EndUserName>>,
    pub(crate) given_name: Option<LocalizedClaim<EndUserGivenName>>,
    pub(crate) family_name: Option<LocalizedClaim<EndUserFamilyName>>,
    pub(crate) middle_name: Option<LocalizedClaim<EndUserMiddleName>>,
    pub(crate) nickname: Option<LocalizedClaim<EndUserNickname>>,
    pub(crate) preferred_username: Option<EndUserUsername>,
    pub(crate) profile: Option<LocalizedClaim<EndUserProfileUrl>>,
    pub(crate) picture: Option<LocalizedClaim<EndUserPictureUrl>>,
    pub(crate) website: Option<LocalizedClaim<EndUserWebsiteUrl>>,
    pub(crate) email: Option<EndUserEmail>,
    pub(crate) email_verified: Option<bool>,
    pub(crate) gender: Option<GC>,
    pub(crate) birthday: Option<EndUserBirthday>,
    pub(crate) zoneinfo: Option<EndUserTimezone>,
    pub(crate) locale: Option<LanguageTag>,
    pub(crate) phone_number: Option<EndUserPhoneNumber>,
    pub(crate) phone_number_verified: Option<bool>,
    pub(crate) address: Option<AddressClaim>,
    pub(crate) updated_at: Option<DateTime<Utc>>,
}
impl<GC> StandardClaims<GC>
where
    GC: GenderClaim,
{
    ///
    /// Initializes a set of Standard Claims.
    ///
    /// The Subject (`sub`) claim is the only required Standard Claim.
    ///
    pub fn new(subject: SubjectIdentifier) -> Self {
        Self {
            sub: subject,
            name: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            preferred_username: None,
            profile: None,
            picture: None,
            website: None,
            email: None,
            email_verified: None,
            gender: None,
            birthday: None,
            zoneinfo: None,
            locale: None,
            phone_number: None,
            phone_number_verified: None,
            address: None,
            updated_at: None,
        }
    }

    ///
    /// Returns the Subject (`sub`) claim.
    ///
    pub fn subject(&self) -> &SubjectIdentifier {
        &self.sub
    }

    ///
    /// Sets the Subject (`sub`) claim.
    ///
    pub fn set_subject(mut self, subject: SubjectIdentifier) -> Self {
        self.sub = subject;
        self
    }

    field_getters_setters![
        pub self [self] ["claim"] {
            set_name -> name[Option<LocalizedClaim<EndUserName>>],
            set_given_name -> given_name[Option<LocalizedClaim<EndUserGivenName>>],
            set_family_name ->
                family_name[Option<LocalizedClaim<EndUserFamilyName>>],
            set_middle_name ->
                middle_name[Option<LocalizedClaim<EndUserMiddleName>>],
            set_nickname -> nickname[Option<LocalizedClaim<EndUserNickname>>],
            set_preferred_username -> preferred_username[Option<EndUserUsername>],
            set_profile -> profile[Option<LocalizedClaim<EndUserProfileUrl>>],
            set_picture -> picture[Option<LocalizedClaim<EndUserPictureUrl>>],
            set_website -> website[Option<LocalizedClaim<EndUserWebsiteUrl>>],
            set_email -> email[Option<EndUserEmail>],
            set_email_verified -> email_verified[Option<bool>],
            set_gender -> gender[Option<GC>],
            set_birthday -> birthday[Option<EndUserBirthday>],
            set_zoneinfo -> zoneinfo[Option<EndUserTimezone>],
            set_locale -> locale[Option<LanguageTag>],
            set_phone_number -> phone_number[Option<EndUserPhoneNumber>],
            set_phone_number_verified -> phone_number_verified[Option<bool>],
            set_address -> address[Option<AddressClaim>],
            set_updated_at -> updated_at[Option<DateTime<Utc>>],
        }
    ];
}
impl<GC> FlattenFilter for StandardClaims<GC>
where
    GC: GenderClaim,
{
    // When another struct (i.e., additional claims) is co-flattened with this one, only include
    // fields in that other struct which are not part of this struct.
    fn should_include(field_name: &str) -> bool {
        !matches!(
            split_language_tag_key(field_name),
            ("sub", None)
                | ("name", _)
                | ("given_name", _)
                | ("family_name", _)
                | ("middle_name", _)
                | ("nickname", _)
                | ("preferred_username", None)
                | ("profile", _)
                | ("picture", _)
                | ("website", _)
                | ("email", None)
                | ("email_verified", None)
                | ("gender", None)
                | ("birthday", None)
                | ("zoneinfo", None)
                | ("locale", None)
                | ("phone_number", None)
                | ("phone_number_verified", None)
                | ("address", None)
                | ("updated_at", None)
        )
    }
}
impl<'de, GC> Deserialize<'de> for StandardClaims<GC>
where
    GC: GenderClaim,
{
    ///
    /// Special deserializer that supports [RFC 5646](https://tools.ietf.org/html/rfc5646) language
    /// tags associated with human-readable client metadata fields.
    ///
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ClaimsVisitor<GC: GenderClaim>(PhantomData<GC>);
        impl<'de, GC> Visitor<'de> for ClaimsVisitor<GC>
        where
            GC: GenderClaim,
        {
            type Value = StandardClaims<GC>;

            fn expecting(&self, formatter: &mut Formatter) -> FormatterResult {
                formatter.write_str("struct StandardClaims")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                deserialize_fields! {
                    map {
                        [sub]
                        [LanguageTag(name)]
                        [LanguageTag(given_name)]
                        [LanguageTag(family_name)]
                        [LanguageTag(middle_name)]
                        [LanguageTag(nickname)]
                        [Option(preferred_username)]
                        [LanguageTag(profile)]
                        [LanguageTag(picture)]
                        [LanguageTag(website)]
                        [Option(email)]
                        [Option(email_verified)]
                        [Option(gender)]
                        [Option(birthday)]
                        [Option(zoneinfo)]
                        [Option(locale)]
                        [Option(phone_number)]
                        [Option(phone_number_verified)]
                        [Option(address)]
                        [Option(DateTime(Seconds(updated_at)))]
                    }
                }
            }
        }
        deserializer.deserialize_map(ClaimsVisitor(PhantomData))
    }
}
impl<GC> Serialize for StandardClaims<GC>
where
    GC: GenderClaim,
{
    #[allow(clippy::cognitive_complexity)]
    fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error>
    where
        SE: Serializer,
    {
        serialize_fields! {
            self -> serializer {
                [sub]
                [LanguageTag(name)]
                [LanguageTag(given_name)]
                [LanguageTag(family_name)]
                [LanguageTag(middle_name)]
                [LanguageTag(nickname)]
                [Option(preferred_username)]
                [LanguageTag(profile)]
                [LanguageTag(picture)]
                [LanguageTag(website)]
                [Option(email)]
                [Option(email_verified)]
                [Option(gender)]
                [Option(birthday)]
                [Option(zoneinfo)]
                [Option(locale)]
                [Option(phone_number)]
                [Option(phone_number_verified)]
                [Option(address)]
                [Option(DateTime(Seconds(updated_at)))]
            }
        }
    }
}
