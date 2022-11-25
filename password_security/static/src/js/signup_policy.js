odoo.define("password_security.signup_policy", function(require) {
    "use strict";

    require("web.dom_ready");
    require("auth_password_policy_signup.policy");
    var policy = require("auth_password_policy");
    var PasswordMeter = require("password_security.Meter");

    var $signupForm = $(".oe_signup_form, .oe_reset_password_form");

    if (!$signupForm.length) {
        return;
    }
    $signupForm.find(".field-password meter").remove();

    var $password = $signupForm.find("#password");
    var password_length = $password.data("password_length");
    var password_lower = $password.data("password_lower");
    var password_upper = $password.data("password_upper");
    var password_numeric = $password.data("password_numeric");
    var password_special = $password.data("password_special");
    var password_estimate = $password.data("password_estimate");

    var meter = new PasswordMeter(
        null,
        new policy.Policy({
            password_length: password_length,
            password_lower: password_lower,
            password_upper: password_upper,
            password_numeric: password_numeric,
            password_special: password_special,
            password_estimate: password_estimate,
        }),
        policy.recommendations
    );
    meter.insertAfter($password);
    $password.on("input", function() {
        meter.update($password.val());
    });
});
