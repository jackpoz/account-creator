<?php
  
  class db {
    
    private $conn;
    
    /* --------------------- ONLY EDIT THE VALUES BELOW THIS LINE --------------------- */
    
    private $host = "localhost";      // IP or hostname of your server.
    private $username = "username";   // Database username.
    private $password = "password";   // Database password.
    private $dbname = "auth";         // Database name (i.e. "auth").
    
    /* --------------------- DO NOT EDIT ANYTHING BELOW THIS LINE --------------------- */
    
    // Create the database connection when this class is instantiated.
    function __construct() {
      
      try {
        
        // Establish a new connection to the database.
        $connection = new PDO("mysql:host=$this->host;dbname=$this->dbname", $this->username, $this->password);
        
        // Set the PDO error mode to Exception.
        $connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $this->conn = $connection;
      }
      catch (PDOException $e) {
        echo "Connection failed: " . $e->getMessage();
      }
    }
    
    // Executes an INSERT query on the database.
    public function insertQuery($query, $params) {
      if ($query) {
        try {
          $stmt = $this->conn->prepare($query);
          $stmt->execute($params);
        }
        catch (PDOException $e) {
          error_log("Error when inserting a new account: " . $e->getMessage());
        }
      }
    }
    
    // Fetches and returns the next row from the result set.
    public function querySingleRow($query, $params) {
      if ($query) {
        $stmt = $this->conn->prepare($query);
        $stmt->execute($params);
        
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        return $row;
      }
      else
        return null;
    }
    
    // Returns an array containing all of the result set rows.
    public function queryMultiRow($query, $params) {
      if ($query) {
        $stmt = $this->conn->prepare($query);
        $stmt->execute($params);
        
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        return $results;
      }
      else
        return null;
    }
    
    // Returns the row count from a PDO result set.
    public function getRowCount($results) {
      
      // We can use the count() function here, because the result set is either
      // an associative or numerical array.
      if ($results) {
        return count($results);
      }
    }
    
    // Returns the last inserted row or sequence.
    public function getLastInsertId() {
      return $this->conn->lastInsertId();
    }
    
    private function calculateSRP6Verifier($username, $password, $salt)
    {
      // algorithm constants
      $g = gmp_init(7);
      $N = gmp_init('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16);

      // calculate first hash
      $h1 = sha1(strtoupper($username . ':' . $password), TRUE);

      // calculate second hash
      $h2 = sha1($salt.$h1, TRUE);

      // convert to integer (little-endian)
      $h2 = gmp_import($h2, 1, GMP_LSW_FIRST);

      // g^h2 mod N
      $verifier = gmp_powm($g, $h2, $N);

      // convert back to a byte array (little-endian)
      $verifier = gmp_export($verifier, 1, GMP_LSW_FIRST);

      // pad to 32 bytes, remember that zeros go on the end in little-endian!
      $verifier = str_pad($verifier, 32, chr(0), STR_PAD_RIGHT);

      // done!
      return $verifier;
    }
    
    // Returns SRP6 parameters to register this username/password combination with
    public function getRegistrationData($username, $password)
    {
      // generate a random salt
      $salt = random_bytes(32);
      
      // calculate verifier using this salt
      $verifier = calculateSRP6Verifier($username, $password, $salt);

      // done - this is what you put in the account table!
      return array($salt, $verifier);
    }
    
    // Close the database connection.
    public function close() {
      $this->conn = null;
    }
    
  }

?>
