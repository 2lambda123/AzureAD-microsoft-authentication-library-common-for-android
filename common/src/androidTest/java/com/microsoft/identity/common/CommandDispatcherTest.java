// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
package com.microsoft.identity.common;

import android.content.Intent;

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.microsoft.identity.common.internal.cache.ICacheRecord;
import com.microsoft.identity.common.internal.commands.BaseCommand;
import com.microsoft.identity.common.internal.commands.Command;
import com.microsoft.identity.common.internal.commands.CommandCallback;
import com.microsoft.identity.common.internal.commands.parameters.CommandParameters;
import com.microsoft.identity.common.internal.commands.parameters.DeviceCodeFlowCommandParameters;
import com.microsoft.identity.common.internal.commands.parameters.InteractiveTokenCommandParameters;
import com.microsoft.identity.common.internal.commands.parameters.RemoveAccountCommandParameters;
import com.microsoft.identity.common.internal.commands.parameters.SilentTokenCommandParameters;
import com.microsoft.identity.common.internal.controllers.BaseController;
import com.microsoft.identity.common.internal.controllers.CommandDispatcher;
import com.microsoft.identity.common.internal.providers.oauth2.AuthorizationResult;
import com.microsoft.identity.common.internal.result.AcquireTokenResult;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;


@RunWith(AndroidJUnit4.class)
public class CommandDispatcherTest {

    private static final String TEST_RESULT_STR = "test_result_str";

    @Test
    public void testCanSubmitSilently() throws InterruptedException {
        final CountDownLatch testLatch = new CountDownLatch(1);

        final BaseCommand<String> testCommand = getTestCommand(testLatch);
        CommandDispatcher.submitSilent(testCommand);
        testLatch.await();
    }

    private TestCommand getTestCommand(final CountDownLatch testLatch) {
        return new TestCommand(
                getEmptyTestParams(),
                new CommandCallback<String, Exception>() {
                    @Override
                    public void onCancel() {
                        Assert.fail();
                        testLatch.countDown();
                    }

                    @Override
                    public void onError(Exception error) {
                        Assert.fail();
                        testLatch.countDown();
                    }

                    @Override
                    public void onTaskCompleted(String s) {
                        Assert.assertEquals(TEST_RESULT_STR, s);
                        testLatch.countDown();
                    }
                }, 0);
    }

    @Test
    public void testSubmitSilentWithParamMutation() throws Exception {
        final CountDownLatch testLatch = new CountDownLatch(1);
        CountDownLatch submitLatch = new CountDownLatch(1);
        CountDownLatch submitLatch1 = new CountDownLatch(1);
        CountDownLatch testLatch2 = new CountDownLatch(1);

        final TestCommand testCommand = new LatchedTestCommand(
                getEmptyTestParams(),
                new CommandCallback<String, Exception>() {
                    @Override
                    public void onCancel() {
                        Assert.fail();
                        testLatch.countDown();
                    }

                    @Override
                    public void onError(Exception error) {
                        Assert.fail();
                        testLatch.countDown();
                    }

                    @Override
                    public void onTaskCompleted(String s) {
                        Assert.assertEquals(TEST_RESULT_STR, s);
                        testLatch.countDown();
                    }
                }, 0, submitLatch, submitLatch1);
        CommandDispatcher.submitSilent(testCommand);
        submitLatch1.await();
        testCommand.value = 2;
        submitLatch.countDown();
        testLatch.await();

        // This is required, because it gives us a guarantee of visibility on the
        // changes made in the sExecutingCommandMap.
        CommandDispatcher.submitSilent(getTestCommand(testLatch2));
        testLatch2.await();

        Assert.assertEquals(0, CommandDispatcher.outstandingCommands());
    }

    @Test
    public void testSubmitSilentWithException() {
        final CountDownLatch testLatch = new CountDownLatch(1);
        CommandDispatcher.submitSilent(new ExceptionCommand(getEmptyTestParams(),
                new CommandCallback<String, Exception>() {
                    @Override
                    public void onCancel() {
                        Assert.fail();
                        testLatch.countDown();
                    }

                    @Override
                    public void onError(Exception error) {
                        testLatch.countDown();
                    }

                    @Override
                    public void onTaskCompleted(String s) {
                        Assert.fail();
                        testLatch.countDown();
                    }
                }));
    }

    static class ExceptionCommand extends BaseCommand<String> {

        public ExceptionCommand(@NonNull final CommandParameters parameters,
                                @NonNull final CommandCallback callback) {
            super(parameters, getTestController(), callback, "test_id");
        }

        @Override
        public String execute() {
            throw new RuntimeException("An unexpected exception!");
        }

        @Override
        public boolean isEligibleForEstsTelemetry() {
            return false;
        }
    }


    static class TestCommand extends BaseCommand<String> {
        public int value;

        public TestCommand(@NonNull final CommandParameters parameters,
                           @NonNull final CommandCallback callback, int value) {
            super(parameters, getTestController(), callback, "test_id");
            this.value = value;
        }

        @Override
        public String execute() {
            return TEST_RESULT_STR;
        }

        @Override
        public boolean isEligibleForEstsTelemetry() {
            return false;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            if (!super.equals(o)) return false;
            TestCommand that = (TestCommand) o;
            return value == that.value;
        }

        @Override
        public int hashCode() {
            return Objects.hash(super.hashCode(), value);
        }
    }

    public static class LatchedTestCommand extends TestCommand {
        final CountDownLatch latch;
        final CountDownLatch latch1;

        public LatchedTestCommand(@NonNull final CommandParameters parameters,
                                  @NonNull final CommandCallback callback,
                                  final int value,
                                  @NonNull final CountDownLatch latch,
                                  @NonNull final CountDownLatch latch1) {
            super(parameters, callback, value);
            this.latch = latch;
            this.latch1 = latch1;
        }

        @Override
        public String execute() {
            latch1.countDown();
            try {
                latch.await();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            return super.execute();
        }
    }

    private static BaseController getTestController() {
        return new BaseController() {
            @Override
            public AcquireTokenResult acquireToken(InteractiveTokenCommandParameters request) throws Exception {
                return null;
            }

            @Override
            public void completeAcquireToken(int requestCode, int resultCode, Intent data) {

            }

            @Override
            public AcquireTokenResult acquireTokenSilent(SilentTokenCommandParameters parameters) throws Exception {
                return null;
            }

            @Override
            public List<ICacheRecord> getAccounts(CommandParameters parameters) throws Exception {
                return null;
            }

            @Override
            public boolean removeAccount(RemoveAccountCommandParameters parameters) throws Exception {
                return false;
            }

            @Override
            public boolean getDeviceMode(CommandParameters parameters) throws Exception {
                return false;
            }

            @Override
            public List<ICacheRecord> getCurrentAccount(CommandParameters parameters) throws Exception {
                return null;
            }

            @Override
            public boolean removeCurrentAccount(RemoveAccountCommandParameters parameters) throws Exception {
                return false;
            }

            @Override
            public AuthorizationResult deviceCodeFlowAuthRequest(DeviceCodeFlowCommandParameters parameters) throws Exception {
                return null;
            }

            @Override
            public AcquireTokenResult acquireDeviceCodeFlowToken(AuthorizationResult authorizationResult, DeviceCodeFlowCommandParameters parameters) throws Exception {
                return null;
            }
        };
    }

    private static CommandParameters getEmptyTestParams() {
        return CommandParameters.builder().build();
    }
}
