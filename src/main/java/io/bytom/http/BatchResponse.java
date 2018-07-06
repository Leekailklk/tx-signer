package io.bytom.http;

import io.bytom.common.Utils;
import io.bytom.exception.BytomException;

import java.util.*;

/**
 * BatchResponse provides a convenient interface for handling the results of
 * batched API calls. The response contains one success or error per outgoing
 * request item in the batch. Errors are always of type BytomException.
 */
public class BatchResponse<T> {
    private Map<Integer, T> successesByIndex = new LinkedHashMap<>();
    private Map<Integer, BytomException> errorsByIndex = new LinkedHashMap<>();

    public String toJson() {
        return Utils.serializer.toJson(this);
    }

    /**
     * This constructor is used for synthetically generating a batch response
     * object from a map of successes and a map of errors. It ensures that
     * the successes and errors are stored in an order-preserving fashion.
     */
    public BatchResponse(Map<Integer, T> successes, Map<Integer, BytomException> errors) {
        List<Integer> successIndexes = new ArrayList<>();
        Iterator<Integer> successIter = successes.keySet().iterator();
        while (successIter.hasNext()) {
            successIndexes.add(successIter.next());
        }
        Collections.sort(successIndexes);

        for (int i : successIndexes) {
            successesByIndex.put(i, successes.get(i));
        }

        List<Integer> errorIndexes = new ArrayList<>();
        Iterator<Integer> errorIter = errors.keySet().iterator();
        while (errorIter.hasNext()) {
            errorIndexes.add(errorIter.next());
        }
        Collections.sort(errorIndexes);
        for (int i : errorIndexes) {
            errorsByIndex.put(i, errors.get(i));
        }
    }

    /**
     * Returns the total number of response objects. This should equal the number
     * of request objects in the batch.
     */
    public int size() {
        return successesByIndex.size() + errorsByIndex.size();
    }

    /**
     * Returns whether the request object at the given index produced a success.
     *
     * @param index the index of the request object
     */
    public boolean isSuccess(int index) {
        return successesByIndex.containsKey(index);
    }

    /**
     * Returns whether the request object at the given index produced an error.
     *
     * @param index the index of the request object
     */
    public boolean isError(int index) {
        return errorsByIndex.containsKey(index);
    }

    /**
     * Returns a list of successful response objects in the batch. The order of
     * the list corresponds to the order of the request objects that produced the
     * successes.
     */
    public List<T> successes() {
        List<T> res = new ArrayList<>();
        res.addAll(successesByIndex.values());
        return res;
    }

    /**
     * Returns a list of error objects in the batch. The order of the list
     * corresponds to the order of the request objects that produced the
     * errors.
     */
    public List<BytomException> errors() {
        List<BytomException> res = new ArrayList<>();
        res.addAll(errorsByIndex.values());
        return res;
    }

    /**
     * Returns a map of success responses, keyed by the index of the request
     * object that produced the success. The set of this map's keys is mutually
     * exclusive of the keys returned by errorsByIndex.
     */
    public Map<Integer, T> successesByIndex() {
        return successesByIndex;
    }

    /**
     * Returns a map of error responses, keyed by the index of the request
     * object that produced the error. The set of this map's keys is mutually
     * exclusive of the keys returned by successByIndex.
     */
    public Map<Integer, BytomException> errorsByIndex() {
        return errorsByIndex;
    }
}
