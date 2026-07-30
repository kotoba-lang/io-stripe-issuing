(ns io.stripe.issuing.core
  "A live Stripe Issuing provider for kotoba.card.actuation.

  This is the layer that actually issues a card, and it is deliberately the only
  thing in this family that can: `kotoba.card.ports` is propose-only, and
  `kotoba.card.actuation` is the post-approval contract this implements. Same
  arrangement as kotoba-lang/drive (contract) + io-storj (provider): neither
  library depends on the other, and a host depends on both.

  WHAT IS AND IS NOT VERIFIED, because the difference decides how much you may
  trust this before running it:

    Verified against the live Stripe API spec on 2026-07-30 (2026-06-24.preview):
      - GET /v1/issuing/cards and /v1/issuing/cardholders exist
      - card status is one of active / inactive / canceled
      - card type is one of virtual / physical

    NOT verified through tooling, written from knowledge of the API:
      - the POST bodies (/v1/issuing/cardholders, /v1/issuing/cards) and the
        replacement_for / cancellation_reason fields
    The MCP surface available here exposes only read operations for Issuing, so the
    write shapes could not be checked the way the statuses were. Treat every write
    path as unexercised until it has run against Stripe TEST MODE. `mode` defaults
    to :test for exactly this reason and `live?` must be set deliberately.

  NO CREDENTIAL LIVES HERE. The secret key is read from an environment variable
  named by the caller, and never logged -- `describe` redacts it. The transport is
  injected, so the whole provider is testable without a network and without a key.

  Every write goes through `actuation/precheck` FIRST: an approval naming both who
  and what, plus a caller-supplied idempotency key. A provider that reached the
  network and then discovered the approval was unnamed would already have acted."
  (:require [clojure.data.json :as json]
            [clojure.string :as str]
            [kotoba.card.actuation :as actuation]
            [kotoba.card.lifecycle :as lifecycle]
            [io.stripe.issuing.state :as state])
  (:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers
            HttpResponse$BodyHandlers]
           [java.time Duration]))

(def api-base "https://api.stripe.com")

(defonce ^HttpClient default-client
  (-> (HttpClient/newBuilder)
      (.connectTimeout (Duration/ofSeconds 10))
      (.build)))

;; ---------------------------------------------------------------------------
;; form encoding -- Stripe takes application/x-www-form-urlencoded, including for
;; nested objects, which it expects as name[child]=value
;; ---------------------------------------------------------------------------

(defn- enc [s]
  (java.net.URLEncoder/encode (str s) "UTF-8"))

(defn form-encode
  "Encode a nested map the way Stripe expects: name[child]=value.

  Written out rather than reached for from a library because the nesting rule is
  the one thing about Stripe's wire format that is easy to get subtly wrong, and a
  wrong body here means a card created with the wrong shape."
  ([m] (str/join "&" (form-encode m nil)))
  ([m prefix]
   (mapcat
    (fn [[k v]]
      (let [key-name (if prefix (str prefix "[" (name k) "]") (name k))]
        (cond
          (map? v) (form-encode v key-name)
          (sequential? v) (map-indexed
                           (fn [i x] (str (enc (str key-name "[" i "]")) "=" (enc x)))
                           v)
          (nil? v) []
          :else [(str (enc key-name) "=" (enc v))])))
    m)))

;; ---------------------------------------------------------------------------
;; transport
;; ---------------------------------------------------------------------------

(defn http-transport
  "The real transport. Returns (fn [method path body idempotency-key] -> response-map).

  `secret-key-env` names the environment variable holding the key; the key is read
  at call time and never stored on the record, so a provider value cannot leak one
  by being printed."
  ([secret-key-env] (http-transport secret-key-env default-client))
  ([secret-key-env ^HttpClient client]
   (fn [method path body idempotency-key]
     (let [key (System/getenv secret-key-env)]
       (if (str/blank? (str key))
         {:status 0 :error (str secret-key-env " が未設定です")}
         (try
           (let [payload (when body (form-encode body))
                 builder (-> (HttpRequest/newBuilder (URI/create (str api-base path)))
                             (.timeout (Duration/ofSeconds 30))
                             (.header "Authorization" (str "Bearer " key))
                             (.header "Stripe-Version" "2026-06-24.preview"))
                 builder (cond-> builder
                           idempotency-key (.header "Idempotency-Key" idempotency-key)
                           payload (.header "Content-Type"
                                            "application/x-www-form-urlencoded"))
                 request (case method
                           :get (.build (.GET builder))
                           :post (.build (.POST builder
                                                (HttpRequest$BodyPublishers/ofString
                                                 (or payload ""))))
                           (throw (ex-info "unsupported method" {:method method})))
                 response (.send client request (HttpResponse$BodyHandlers/ofString))]
             {:status (.statusCode response)
              :body (try (json/read-str (.body response) :key-fn keyword)
                         (catch Exception _ nil))})
           (catch Exception e
             {:status 0 :error (.getMessage e)})))))))

(defn recorded-transport
  "A transport that answers from a map of {[method path] response} and records
  every call. For tests, and for a caller that wants to see what would be sent
  without sending it."
  [responses calls]
  (fn [method path body idempotency-key]
    (swap! calls conj {:method method :path path :body body
                       :idempotency-key idempotency-key})
    (get responses [method path]
         {:status 404 :body {:error {:message (str "no recorded response for "
                                                   method " " path)}}})))

;; ---------------------------------------------------------------------------
;; provider
;; ---------------------------------------------------------------------------

(defn- stripe-error [{:keys [status body error]}]
  (actuation/refusal
   :stripe-error
   (cond-> {:status status}
     error (assoc :detail error)
     (get-in body [:error :message]) (assoc :message (get-in body [:error :message]))
     (get-in body [:error :code]) (assoc :code (get-in body [:error :code])))))

(defn- ok? [{:keys [status]}] (and (number? status) (<= 200 status 299)))

(defrecord StripeIssuing [transport mode]
  actuation/ICardholderActuation
  (create-cardholder! [_ application approval idempotency-key]
    (or (actuation/precheck approval idempotency-key)
        (let [body {:name (:name application)
                    :email (:email application)
                    :phone_number (:phone application)
                    :status "active"
                    :type (or (:cardholder-type application) "individual")
                    :billing {:address {:line1 (:line1 application)
                                        :city (:city application)
                                        :country (:country application)
                                        :postal_code (:postal-code application)}}}
              res (transport :post "/v1/issuing/cardholders" body idempotency-key)]
          (if (ok? res)
            {:card/ok? true
             :card/cardholder-id (get-in res [:body :id])
             :card/provider-record (:body res)}
            (stripe-error res)))))

  (cardholder [_ cardholder-id]
    (let [res (transport :get (str "/v1/issuing/cardholders/" cardholder-id) nil nil)]
      (when (ok? res) (:body res))))

  actuation/ICardActuation
  (issue-card! [_ cardholder program approval idempotency-key]
    (or (actuation/precheck approval idempotency-key)
        (let [card-type (or (:card-type program) "virtual")]
          (if-not (contains? state/card-types card-type)
            (actuation/refusal :card-type-unsupported
                               {:detail (str "Stripe の type は "
                                             (str/join " / " (sort state/card-types))
                                             " のみです: " card-type)})
            ;; A new card is created "inactive", which is the provider side of
            ;; lifecycle :issued -- NOT :active. Creating it active would skip the
            ;; activation the issuer side models as its own gated event.
            (let [body (cond-> {:cardholder cardholder
                                :currency (or (:currency program) "usd")
                                :type card-type
                                :status (state/->stripe :issued)}
                         (:spending-limit-minor program)
                         (assoc :spending_controls
                                {:spending_limits
                                 [{:amount (:spending-limit-minor program)
                                   :interval (or (:spending-limit-interval program)
                                                 "daily")}]}))
                  res (transport :post "/v1/issuing/cards" body idempotency-key)]
              (if (ok? res)
                {:card/ok? true
                 :card/reference (get-in res [:body :id])
                 :card/state :issued
                 :card/provider-record (:body res)}
                (stripe-error res)))))))

  (set-card-state! [_ reference event approval idempotency-key]
    (or (actuation/precheck approval idempotency-key)
        (let [op (state/event->op event)]
          (cond
            (nil? op)
            (actuation/refusal :event-unknown {:event event})

            ;; A reissue is two calls at Stripe, not a status change. Refusing it
            ;; here rather than approximating it with a cancel keeps the caller
            ;; from believing a replacement card exists when none does.
            (= :replace (:stripe/op op))
            (actuation/refusal
             :reissue-not-a-status-change
             {:detail (:stripe/detail op)
              :hint (str "cancel the original and issue-card! a replacement as two "
                         "separately approved actuations")})

            :else
            (let [res (transport :post (str "/v1/issuing/cards/" reference)
                                 {:status (:stripe/status op)} idempotency-key)]
              (if (ok? res)
                {:card/ok? true
                 :card/reference reference
                 :card/state (get-in lifecycle/events [event :to])
                 :card/provider-record (:body res)}
                (stripe-error res)))))))

  (card-state [_ reference]
    ;; Returns the CANDIDATES, not a state. "inactive" is both :issued and
    ;; :blocked, so answering with one of them would tell a caller that a
    ;; deliberately-blocked card is merely un-activated. The issuer side's own
    ;; recorded state is the authority; this is corroboration, not truth.
    (let [res (transport :get (str "/v1/issuing/cards/" reference) nil nil)]
      (when (ok? res)
        (let [status (get-in res [:body :status])]
          {:stripe/status status
           :card/candidates (state/stripe->candidates status)
           :card/unambiguous (let [c (state/stripe->candidates status)]
                               (when (= 1 (count c)) (first c)))})))))

(defn provider
  "A Stripe Issuing provider.

  opts:
    :transport   -- (fn [method path body idempotency-key] -> response-map).
                    Defaults to the real HTTP transport reading :secret-key-env.
    :secret-key-env -- env var holding the Stripe secret key (default
                    STRIPE_SECRET_KEY). Read at call time, never stored.
    :mode        -- :test (default) or :live. Nothing here enforces which key you
                    supply; the field records intent so a caller can refuse to run
                    a live provider by accident, and `describe` reports it."
  [& {:keys [transport secret-key-env mode]
      :or {secret-key-env "STRIPE_SECRET_KEY" mode :test}}]
  (->StripeIssuing (or transport (http-transport secret-key-env)) mode))

(defn describe
  "What this provider is, for a log or an operator screen. Carries no secret --
  the key is read from the environment at call time and is not on the record."
  [^StripeIssuing p]
  {:provider "stripe-issuing"
   :mode (:mode p)
   :api-version "2026-06-24.preview"
   :state-mapping state/mapping
   :unrepresentable (actuation/unrepresentable-states state/mapping)
   :ambiguous-stripe-statuses (state/ambiguous-statuses)
   :write-paths-unexercised true})
