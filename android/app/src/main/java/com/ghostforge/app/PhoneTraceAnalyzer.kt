package com.ghostforge.app

import com.google.i18n.phonenumbers.NumberParseException
import com.google.i18n.phonenumbers.PhoneNumberUtil
import java.util.Locale

/**
 * Offline numbering-plan metadata for a user-entered phone number.
 * NOT an identity lookup, carrier verification, caller authentication or GPS trace.
 */
data class PhoneTraceReport(
    val international: String,
    val e164: String,
    val numberingRegion: String,
    val countryCallingCode: String,
    val category: String,
    val possible: Boolean,
    val validPattern: Boolean,
    val geographicPrefix: String?,
    val warnings: List<String>,
    val disclaimer: String = "Numbering-plan metadata isn't the caller's current location. " +
        "A phone number alone cannot prove identity, carrier, GPS location, whether it's active, " +
        "or whether it's a scam. Caller ID can be spoofed and numbers can be ported."
)

object PhoneTraceAnalyzer {
    private val util: PhoneNumberUtil = PhoneNumberUtil.getInstance()
    private val allowed = Regex("""^[+0-9()\s.\-]{3,40}$""")
    private val isoRegion = Regex("""^[A-Z]{2}$""")

    fun inspect(raw: String, defaultRegion: String): Result<PhoneTraceReport> = runCatching {
        val input = raw.trim()
        require(input.matches(allowed)) {
            "Enter a phone number using only digits, +, spaces, parentheses, dots or hyphens."
        }
        val region = defaultRegion.trim().uppercase(Locale.ROOT)
        require(region.matches(isoRegion) && util.getCountryCodeForRegion(region) != 0) {
            "Enter a supported two-letter default region, such as CA, US or GB."
        }
        val number = try {
            util.parse(input, region)
        } catch (error: NumberParseException) {
            throw IllegalArgumentException("Cannot parse that number. Include its country code, e.g. +1.")
        }
        val possible = util.isPossibleNumber(number)
        val valid = util.isValidNumber(number)
        val assignedRegion = util.getRegionCodeForNumber(number).orEmpty()
            .ifBlank { "Unknown" }
        val type = util.getNumberType(number)
        val category = when (type) {
            PhoneNumberUtil.PhoneNumberType.MOBILE -> "Mobile numbering range"
            PhoneNumberUtil.PhoneNumberType.FIXED_LINE -> "Fixed-line numbering range"
            PhoneNumberUtil.PhoneNumberType.FIXED_LINE_OR_MOBILE ->
                "Fixed-line or mobile (not distinguishable)"
            PhoneNumberUtil.PhoneNumberType.VOIP -> "VoIP numbering range"
            PhoneNumberUtil.PhoneNumberType.TOLL_FREE -> "Toll-free numbering range"
            PhoneNumberUtil.PhoneNumberType.PREMIUM_RATE -> "Premium-rate numbering range"
            PhoneNumberUtil.PhoneNumberType.SHARED_COST -> "Shared-cost numbering range"
            PhoneNumberUtil.PhoneNumberType.PERSONAL_NUMBER -> "Personal-number range"
            PhoneNumberUtil.PhoneNumberType.PAGER -> "Paging numbering range"
            PhoneNumberUtil.PhoneNumberType.UAN -> "Universal access numbering range"
            PhoneNumberUtil.PhoneNumberType.VOICEMAIL -> "Voicemail numbering range"
            else -> "Unknown / unclassified number type"
        }
        val warnings = mutableListOf<String>()
        if (!possible) warnings.add("This number doesn't fit the expected numbering-plan length.")
        if (possible && !valid) warnings.add(
            "The number is possible by length, but isn't a recognized numbering pattern.")
        if (valid) warnings.add(
            "A valid numbering pattern does NOT prove this number is assigned, reachable or safe.")
        if (type == PhoneNumberUtil.PhoneNumberType.PREMIUM_RATE) {
            warnings.add("Premium-rate numbers may incur high call charges. Don't call back an unknown number.")
        }
        if (type == PhoneNumberUtil.PhoneNumberType.VOIP) {
            warnings.add("VoIP classification is assigned-range metadata, not a current-carrier lookup.")
        }
        val national = util.getNationalSignificantNumber(number)
        // North American Numbering Plan area prefix is not the user's current location.
        val npa = if (number.countryCode == 1 && national.length == 10) national.take(3) else null
        PhoneTraceReport(
            international = util.format(number, PhoneNumberUtil.PhoneNumberFormat.INTERNATIONAL),
            e164 = util.format(number, PhoneNumberUtil.PhoneNumberFormat.E164),
            numberingRegion = when (assignedRegion) {
                "001" -> "Non-geographic international numbering plan"
                "Unknown" -> "Unknown / unassigned region"
                else -> Locale("", assignedRegion).displayCountry.ifBlank { assignedRegion } +
                    " (" + assignedRegion + ")"
            },
            countryCallingCode = "+" + number.countryCode,
            category = category,
            possible = possible,
            validPattern = valid,
            geographicPrefix = npa,
            warnings = warnings
        )
    }
}
