uses gw.api.database.Query
class BadGosu {
  function find(n : String) {
    var q = "SELECT * FROM pc_policy WHERE name = '" + n + "'"
    eval(n)
  }
}
