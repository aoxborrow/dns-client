/**
 * where a dataset the library bundles comes from, and how fresh it is. Each bundled dataset
 * has one, named after it: `ROOT_HINTS_INFO` for `ROOT_HINTS`, and so on
 */
export interface DatasetInfo {
  /** the URL the data is taken from */
  readonly source: string;
  /**
   * names the bundled data, and changes whenever the data does. For data copied from its
   * source, the source's own version where it has one, else the date the data last changed.
   * Left out where neither is known
   */
  readonly version?: string;
  /** the day the data was last checked against its source, `YYYY-MM-DD` */
  readonly refreshed: string;
}
