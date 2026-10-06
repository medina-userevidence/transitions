import { ActionRule, RebacSchema, ResolveRelation, Subject } from '@inixiative/permissions';
export { ActionRule } from '@inixiative/permissions';
import { Condition, RuleValue, DateConfig, Lens, LensNarrowing } from '@inixiative/json-rules';

type Row = Record<string, unknown>;

type Actor = ({
    id?: string | null;
} & Row) | null | undefined;
/**
 * Injected permission evaluator. Resource-free: the kernel knows nothing about resources or schemas,
 * so the consumer closes over whatever its rebac needs (see {@link createAuthorize}, the adapter
 * over `@inixiative/permissions`).
 */
type Authorize = (rule: ActionRule, record: Row, actor: Actor) => boolean;
/** Serializable merge keywords (Mongo-flavored). Array strategies are field-scoped. */
type MergeStrategy = 'spread' | 'deepMerge' | {
    kind: 'append';
    path: string;
} | {
    kind: 'appendUnique';
    path: string;
};
/** A merge is a raw callback (full power, NOT serializable) or a serializable keyword strategy. */
type Merge<R extends Row = Row> = ((record: R, changes: Partial<R>) => R) | MergeStrategy;
/** Prisma-include-shaped metadata: the relations a side's predicate reads. Kernel ignores it. */
type Include = Record<string, unknown>;
/**
 * One half of a transition. `predicate` (legality) and `permission` (authz) are both evaluated
 * against the SAME record — the load-bearing asymmetry is WHICH record: `from.*` reads the
 * CURRENT record, `to.*` reads the RESULTING (merged) record.
 */
type Side = {
    predicate: Condition;
    permission?: ActionRule;
    requires?: Include;
};
type ToSide<R extends Row = Row> = Side & {
    merge?: Merge<R>;
};
/** An atomic edge: `from → to`. Disjunction lives at the action level, never here. */
type Transition<R extends Row = Row> = {
    from: Side;
    to: ToSide<R>;
};
/**
 * A named verb: the OR of its edges. An object (not a bare `Transition[]`) so the action can
 * carry affordance metadata (`label`). Authorization lives on the per-side `permission`s, which
 * always read a concrete record — there is no record-free action-level permission.
 */
type Action<R extends Row = Row> = {
    paths: Transition<R>[];
    label?: string;
};
/** `resource → action → Action`, where `resource` is the (map-qualified) key — e.g. `db:Inquiry`,
 *  matching `@inixiative/permissions`' rebac schema keys so a transition's `permission` resolves
 *  against the same resource identity. */
type TransitionMap = Record<string, Record<string, Action>>;
/** Why one side failed. Both keys are independent; either, both, or neither may be set. */
type SideReason = {
    predicate?: string;
    permission?: string;
};
/** Why one candidate path failed — `from` and `to` reported separately. */
type PathReason = {
    from?: SideReason;
    to?: SideReason;
};
/** Why an action failed: one {@link PathReason} per candidate path that was tried. */
type Reason = {
    paths: PathReason[];
};
/** `true` when the transition is allowed, else a structured {@link Reason}. */
type CheckResult = true | Reason;
/** Options threaded into a check. Omit `authorize` to evaluate legality only. */
type AuthorizeOptions = {
    actor?: Actor;
    authorize?: Authorize;
};
/**
 * What a predicate is evaluated WITH: the clock for relative date expressions and the values
 * of its `{ bind }` tokens. Passed straight to json-rules — the same `now` / `bindings` a bare
 * `check()` takes, so one declaration serves a single record and the {@link eligible} set query.
 */
type EvaluationOptions = {
    bindings?: Record<string, RuleValue>;
} & DateConfig;
type CheckOptions = AuthorizeOptions & EvaluationOptions;

type PermissionsAuthorizeOptions<R extends string = string> = {
    /** The permissions rebac schema: `{ bridges?, permissions }`. */
    schema: RebacSchema<R>;
    /**
     * Resolve a hydrated relation field to the resource it points at (the ORM-specific seam).
     * Default: the relation segment name doubles as the resource key. Cross-map bridges are resolved
     * by the engine from `schema.bridges`, not here.
     */
    resolveRelation?: ResolveRelation<R>;
    /** Superadmin bypass, derived from the actor; checked before any rule. */
    isSuperadmin?: (actor: Actor) => boolean;
    /**
     * Supplemental hydrated rows (`map:model → rows`) for bridge (cross-map) `rel` walks, derived from
     * the record + actor — the same shape `Subject.data` takes. Only consulted when a walk crosses a
     * bridge and a downstream action reads the far record's fields.
     */
    data?: (record: Row, actor: Actor) => Subject<R>['data'];
};
/**
 * Bridge `@inixiative/permissions`' rebac `check` onto transitions' {@link Authorize} seam — the
 * production evaluator, injected, not reimplemented. `createAuthorize(options)(resource)` returns an
 * `Authorize` bound to a (map-qualified) `resource`; each call evaluates a per-side `permission`
 * rule against a concrete record + actor. permissions owns the evaluation (string delegation with
 * cycle detection, intra-map `rel` walks via `resolveRelation`, cross-map bridge walks, `{ self }`,
 * abac `{ rule }`, boolean terminals, `any`/`all`, per-row `permissionRules` overrides).
 */
declare const createAuthorize: <R extends string = string>(options: PermissionsAuthorizeOptions<R>) => ((resource: R) => Authorize);

/**
 * The kernel: evaluate one atomic edge. Reports every failure rather than short-circuiting —
 * `from`/`to` and predicate/permission are independent slots — so a caller sees the whole
 * picture. `from.*` reads the current `record`, `to.*` reads the merged `next` record. Returns
 * `true` when the edge is allowed, else the {@link PathReason}. Omit `authorize` for legality only;
 * `now` / `bindings` reach both predicates.
 */
declare const checkPath: <R extends Row>(transition: Transition<R>, record: R, changes?: Partial<R>, options?: CheckOptions) => true | PathReason;

/** Build a human-readable message from a structured {@link Reason} (logs / UI / error bodies). */
declare const describe: (reason: Reason) => string;

/** A transition is persistable iff its merge is absent or a keyword strategy (callbacks are not). */
declare const isSerializableMerge: (merge?: Merge) => boolean;
/**
 * Produce the resulting record from a current record + proposed changes.
 *
 * - `spread` (default) — shallow overwrite (`{ ...record, ...changes }`)
 * - `deepMerge` — recursive object merge, arrays replaced
 * - `{ kind: 'append', path }` — concat `changes[path]` onto `record[path]`
 * - `{ kind: 'appendUnique', path }` — append + dedupe (deep equality)
 * - a callback — full power, not serializable
 */
declare const applyMerge: <R extends Row>(merge: Merge<R> | undefined, record: R, changes?: Partial<R>) => R;

/**
 * Authoritative check: the FIRST path whose `from` matches the current record, whose `to` matches
 * the merged record, and whose permissions all pass, wins → `true`. If none pass, returns a
 * {@link Reason} with one {@link PathReason} per candidate path tried.
 *
 * `resource` is the (map-qualified) key into the map — e.g. `db:Inquiry`. Cross-source `permission`
 * checks are handled by the injected {@link Authorize} (wire it to a bridge-aware rebac check, bound
 * to this resource); a `predicate` that reads a bridged relation expects a stitched record.
 */
declare const checkTransition: (rules: TransitionMap, resource: string, action: string, record: Row, changes?: Row, options?: CheckOptions) => CheckResult;
/**
 * Affordance hint: which actions are offerable from `record` right now. Evaluates ONLY the `from`
 * side (predicate + `from` permission against the current record) — `to` needs the merged record,
 * which doesn't exist without proposed changes, so it defers to {@link checkTransition}.
 */
declare const available: (rules: TransitionMap, resource: string, record: Row, options?: CheckOptions) => string[];
/**
 * Set query: one OR'd Prisma `where` matching every record currently eligible for `action`
 * (the union of all its paths' `from` predicates). Empty action → match-nothing. `bindings` are
 * resolved into the predicate before compiling and `now` anchors relative date expressions, so a
 * guard that reads `{ bind }` or `{ ago }` compiles to the same rows it accepts one at a time.
 */
declare const eligible: (rules: TransitionMap, resource: string, action: string, options?: EvaluationOptions) => Row;

/**
 * Can this transition be persisted (stored in the DB, edited in a UI, sent over the wire)?
 *
 * Predicates (json-rules) and permissions (ActionRule) are always plain JSON; the only
 * non-data escape hatch is a `to.merge` callback. So serializability reduces to the merge.
 */
declare const isSerializable: (transition: Transition) => boolean;

type ValidationIssue = {
    path: string;
    message: string;
};
type ValidationResult = {
    ok: boolean;
    errors: ValidationIssue[];
};
type ValidateOptions = {
    /** Optional field/relation allowlist; passed through to json-rules lens validation per predicate. */
    lens?: Lens | LensNarrowing;
    /** Reject callback merges (use when the transition must be persistable / tenant-configured). */
    requireSerializable?: boolean;
};
/**
 * Authoring validation for a single transition — run on save before persisting a tenant config.
 * Returns structured issues (never throws) on malformed input: predicate validity delegates to
 * json-rules (`validateRule`, plus `checkRuleAgainstLens` when a `lens` is supplied for
 * field/relation scoping); permission shape delegates to `@inixiative/permissions`' `actionRuleSchema`;
 * merge strategy is checked here.
 */
declare const validateTransition: (transition: Transition, options?: ValidateOptions) => ValidationResult;

export { type Action, type Actor, type Authorize, type AuthorizeOptions, type CheckOptions, type CheckResult, type EvaluationOptions, type Include, type Merge, type MergeStrategy, type PathReason, type PermissionsAuthorizeOptions, type Reason, type Row, type Side, type SideReason, type ToSide, type Transition, type TransitionMap, type ValidateOptions, type ValidationIssue, type ValidationResult, applyMerge, available, checkPath, checkTransition, createAuthorize, describe, eligible, isSerializable, isSerializableMerge, validateTransition };
