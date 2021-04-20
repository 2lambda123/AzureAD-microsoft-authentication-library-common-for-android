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
package com.microsoft.identity.common.internal.telemetry.events;

import static com.microsoft.identity.common.java.internal.telemetry.TelemetryEventStrings.Event;
import static com.microsoft.identity.common.java.internal.telemetry.TelemetryEventStrings.EventType;
import static com.microsoft.identity.common.java.internal.telemetry.TelemetryEventStrings.Key;

public class BrokerStartEvent extends com.microsoft.identity.common.java.internal.telemetry.events.BaseEvent {
    public BrokerStartEvent() {
        super();
        names(Event.BROKER_START_EVENT);
        types(EventType.BROKER_EVENT);
    }

    public BrokerStartEvent putAction(final String actionName) {
        put(Key.BROKER_ACTION, actionName);
        return this;
    }

    public BrokerStartEvent putStrategy(final String strategyName) {
        put(Key.BROKER_STRATEGY, strategyName);
        return this;
    }
}
