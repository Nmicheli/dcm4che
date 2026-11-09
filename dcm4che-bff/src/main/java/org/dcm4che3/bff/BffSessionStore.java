/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is part of dcm4che, an implementation of DICOM(TM) in
 * Java(TM), hosted at https://github.com/gunterze/dcm4che.
 *
 * The Initial Developer of the Original Code is
 * Agfa Healthcare.
 * Portions created by the Initial Developer are Copyright (C) 2011-2014
 * the Initial Developer. All Rights Reserved.
 *
 * ***** END LICENSE BLOCK ***** */

package org.dcm4che3.bff;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory store of BFF sessions.
 * <p>
 * Sessions are indexed by an opaque, unguessable identifier, which is the only
 * thing handed to the browser. Expired sessions are evicted lazily, on access and
 * on creation, so the store does not grow without bounds in a long running
 * deployment.
 * <p>
 * A clustered deployment should provide a shared implementation of this class,
 * e.g. backed by Infinispan or by the database.
 *
 * @author dcm4che
 */
public class BffSessionStore {

    private final Map<String, BffSession> sessions = new ConcurrentHashMap<String, BffSession>();
    private final int idleTimeoutSeconds;
    private final int maxSessions;
    private final AtomicLong created = new AtomicLong();

    public BffSessionStore(int idleTimeoutSeconds) {
        this(idleTimeoutSeconds, 10000);
    }

    public BffSessionStore(int idleTimeoutSeconds, int maxSessions) {
        this.idleTimeoutSeconds = idleTimeoutSeconds;
        this.maxSessions = maxSessions;
    }

    /**
     * Creates a new session, with a fresh identifier.
     */
    public BffSession create() {
        evictExpired(System.currentTimeMillis());
        BffSession session = new BffSession(TokenSet.randomToken(32), System.currentTimeMillis());
        sessions.put(session.getId(), session);
        created.incrementAndGet();
        return session;
    }

    /**
     * Returns the session with the given identifier, or <code>null</code> if it
     * does not exist or is expired. Access refreshes the idle timeout.
     */
    public BffSession get(String id) {
        if (id == null || id.isEmpty())
            return null;
        BffSession session = sessions.get(id);
        if (session == null)
            return null;
        long now = System.currentTimeMillis();
        if (session.isExpired(now, idleTimeoutSeconds)) {
            sessions.remove(id);
            return null;
        }
        session.touch(now);
        return session;
    }

    /**
     * Returns the session with the given identifier without refreshing its idle
     * timeout.
     */
    public BffSession peek(String id) {
        return id != null ? sessions.get(id) : null;
    }

    public void remove(String id) {
        if (id != null)
            sessions.remove(id);
    }

    public int size() {
        return sessions.size();
    }

    /**
     * Number of sessions created since the store was instantiated.
     */
    public long getCreatedCount() {
        return created.get();
    }

    /**
     * Removes all expired sessions and returns the number of removed entries.
     */
    public int evictExpired(long now) {
        int removed = 0;
        for (Iterator<Map.Entry<String, BffSession>> it = sessions.entrySet().iterator(); it.hasNext();) {
            BffSession session = it.next().getValue();
            if (session.isExpired(now, idleTimeoutSeconds)) {
                it.remove();
                removed++;
            }
        }
        if (sessions.size() > maxSessions)
            evictOldest(sessions.size() - maxSessions);
        return removed;
    }

    private void evictOldest(int count) {
        for (int i = 0; i < count; i++) {
            String oldestId = null;
            long oldest = Long.MAX_VALUE;
            for (BffSession session : sessions.values())
                if (session.getLastAccess() < oldest) {
                    oldest = session.getLastAccess();
                    oldestId = session.getId();
                }
            if (oldestId == null)
                return;
            sessions.remove(oldestId);
        }
    }
}
