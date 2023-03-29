package com.microsoft.identity.common.internal.commands.parameters;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;

@Getter
@EqualsAndHashCode(callSuper = true)
@SuperBuilder(toBuilder = true)
public class SignUpStartCommandParameters extends BaseNativeAuthCommandParameters {
	private static final String TAG = SignUpStartCommandParameters.class.getSimpleName();

	@NonNull
	public final String email;
	public final String password;
	// TODO @EqualsAndHashCode.Exclude?
	public final UserAttributes userAttributes;
}

