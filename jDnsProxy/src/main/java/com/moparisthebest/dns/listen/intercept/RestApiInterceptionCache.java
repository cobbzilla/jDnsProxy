package com.moparisthebest.dns.listen.intercept;

import java.util.List;

public interface RestApiInterceptionCache {

    Long getLastMod ();

    void update(List<String> intercepts, BulkLoadMode mode);

}
