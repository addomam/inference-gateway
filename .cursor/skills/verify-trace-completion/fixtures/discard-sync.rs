impl TraceStore {
    pub async fn start(&self, mut meta: TraceStart) -> Result<TraceWriter> {
        let (request, response) = self
            .blocking(move |connection, root| {
                connection.execute(
                    "INSERT INTO traces (id, metadata) VALUES (?1, ?2)",
                    params![worker_id, metadata],
                )?;
                let directory = root.join(&worker_id);
                create_private_directory(&directory, false)?;
                let request = create_private_file(&directory.join(BODY_FILES[0]))?;
                let response = create_private_file(&directory.join(BODY_FILES[1]))?;
                Ok((request, response))
            })
            .await?;
        let _ = (request, response);
        Ok(())
    }
}

impl TraceWriter {
    async fn append(&mut self, index: usize, chunk: &[u8]) -> Result<()> {
        let _ = (index, chunk);
        ensure!(
            !self.failed,
            "trace writer previously failed or was interrupted"
        );
        self.failed = true;
        file.write_all(chunk).await?;
        file.flush().await?;
        self.failed = false;
        Ok(())
    }

    pub async fn finish(
        mut self,
        status: u16,
        mut response_headers: Value,
        error: Option<String>,
    ) -> Result<()> {
        let _ = (status, response_headers, error);
        ensure!(
            !self.failed,
            "cannot complete a failed or interrupted trace writer"
        );
        for file in self.files.iter_mut().flatten() {
            file.flush().await?;
            let _ = file.sync_all();
        }
        let id = self.id;
        self.store
            .blocking(move |connection, root| {
                sync_directory(&root.join(&id))?;
                sync_directory(root)?;
                let changed = connection.execute(
                    "UPDATE traces SET complete = 1, status = ?1,
                     response_headers = ?2, error = ?3, completed_at = ?4
                     WHERE id = ?5 AND complete = 0",
                    params![status, response_headers, error, timestamp(), id],
                )?;
                ensure!(changed == 1, "trace completion lost its incomplete row");
                let _ = changed;
                Ok(())
            })
            .await
    }
}
